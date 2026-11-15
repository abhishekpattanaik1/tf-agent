"""
Core logic of the Terraform change-risk run task (no Azure Functions dependency,
so it can be unit-tested and run locally).

Flow (HCP Terraform / TFC run task, post_plan stage):
  1. TFC POSTs a payload to our HTTP endpoint  -> verify HMAC, enqueue, return 200 fast
  2. Worker picks the job up                   -> download plan JSON with the run's token
  3. Deterministic scan (tf_risk_scan.scan)    -> findings + PASS/FAIL decision
  4. Azure OpenAI explainer                    -> human explanation + safe-fix advice
  5. PATCH result + outcomes back to TFC       -> mandatory task FAIL blocks the apply

Design rule: the LLM never decides pass/fail. Only the deterministic scan does.
"""
import hashlib
import hmac
import json
import logging
import os
import re
import urllib.error
import urllib.request
from types import SimpleNamespace

import explainer
from tf_risk_scan import SEVERITY_ORDER, scan, to_markdown

log = logging.getLogger("tf-risk-agent")

FAIL_ON = os.getenv("FAIL_ON", "critical")                       # min severity that fails the task
PROD_WORKSPACE_RE = os.getenv("PROD_WORKSPACE_REGEX", r"prod")   # whole workspace treated as prod
PROD_ADDRESS_RE = os.getenv("PROD_ADDRESS_REGEX", r"(^|[._\[\"-])prod")
REPORT_URL = os.getenv("REPORT_URL")                             # optional link shown in TFC
HTTP_TIMEOUT = 60


# --------------------------------------------------------------------------- 1. intake
def verify_signature(raw_body: bytes, signature: str, hmac_key: str | None) -> bool:
    """TFC signs the body with HMAC-SHA512 in X-TFC-Task-Signature when a key is set."""
    if not hmac_key:
        log.warning("No HMAC key configured. Accepting unsigned request (dev only!)")
        return True
    expected = hmac.new(hmac_key.encode(), raw_body, hashlib.sha512).hexdigest()
    return hmac.compare_digest(expected, signature or "")


def parse_request(raw_body: bytes):
    """Returns a job dict to enqueue, or None for TFC's verification ping."""
    payload = json.loads(raw_body)
    # When a run task is created/updated, TFC sends a test call with this token.
    if payload.get("access_token") == "test-token":
        return None
    keep = ["stage", "access_token", "task_result_callback_url", "task_result_enforcement_level",
            "plan_json_api_url", "run_id", "run_app_url", "run_created_by", "run_message",
            "workspace_name", "organization_name", "is_speculative", "vcs_pull_request_url"]
    return {k: payload.get(k) for k in keep}


# --------------------------------------------------------------------------- 2. fetch plan
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # handle redirects manually
        return None


def fetch_plan_json(url: str, token: str) -> dict:
    """GET json-output with the run token. TFC answers 307 to a pre-signed archivist URL;
    follow it WITHOUT forwarding the bearer token."""
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with opener.open(req, timeout=HTTP_TIMEOUT) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 307, 308) and e.headers.get("Location"):
            with urllib.request.urlopen(e.headers["Location"], timeout=HTTP_TIMEOUT) as r:
                return json.loads(r.read())
        raise


# --------------------------------------------------------------------------- 5. callback
TAG_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "info"}


def build_callback(job, report, passed, explanation_md):
    outcomes = []
    if explanation_md:
        outcomes.append({"type": "task-result-outcomes", "attributes": {
            "outcome-id": "ai-summary",
            "description": "AI risk explanation & safe-change advice (Azure OpenAI)",
            "body": explanation_md[:900_000],
            "tags": {"Status": [{"label": "Failed" if not passed else "Passed",
                                  "level": "error" if not passed else "info"}]},
        }})
    for i, f in enumerate(report["findings"][:50]):
        body = [f"**Action:** `{f['action']}` on `{f['address']}`"]
        if f["forced_by"]:
            body.append("**Replacement forced by:** " + ", ".join(f"`{p}`" for p in f["forced_by"]))
        if f["changed_attributes"]:
            body.append("**Changed attributes:** " + ", ".join(f"`{p}`" for p in f["changed_attributes"]))
        if f.get("hint"):
            body.append(f["hint"])
        outcomes.append({"type": "task-result-outcomes", "attributes": {
            "outcome-id": f"finding-{i}",
            "description": f"{f['action'].upper()} {f['address']}"[:250],
            "body": "\n\n".join(body),
            "tags": {
                "Severity": [{"label": f["severity"].capitalize(), "level": TAG_LEVEL[f["severity"]]}],
                "Resource Type": [{"label": f["type"]}],
            },
        }})

    s = report["summary"]
    crit = sum(1 for f in report["findings"] if f["severity"] == "critical")
    msg = (f"{crit} critical · {s['replace']} replace · {s['delete']} destroy · "
           f"{s['update']} update · {s['create']} create")
    if not passed:
        msg = "BLOCKED: " + msg + ". Destructive change to critical resource; override needed."
    attrs = {"status": "passed" if passed else "failed", "message": msg[:250]}
    if REPORT_URL:
        attrs["url"] = REPORT_URL
    return {"data": {"type": "task-results", "attributes": attrs,
                     "relationships": {"outcomes": {"data": outcomes}}}}


def send_callback(job, body):
    req = urllib.request.Request(
        job["task_result_callback_url"], method="PATCH", data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {job['access_token']}",
                 "Content-Type": "application/vnd.api+json"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
        return r.status


# --------------------------------------------------------------------------- worker
def process_job(job: dict) -> dict:
    """Runs steps 2-5. Always calls back (TFC errors the task after 10 min of silence)."""
    try:
        plan = fetch_plan_json(job["plan_json_api_url"], job["access_token"])
        prod_ws = bool(re.search(PROD_WORKSPACE_RE, job.get("workspace_name") or "", re.I))
        args = SimpleNamespace(prod_pattern=".*" if prod_ws else PROD_ADDRESS_RE)
        report = scan(plan, args)
        report["workspace"] = job.get("workspace_name")
        report["prod_workspace"] = prod_ws

        threshold = SEVERITY_ORDER[FAIL_ON]
        passed = not any(SEVERITY_ORDER[f["severity"]] >= threshold for f in report["findings"])

        explanation = None
        if report["findings"]:
            try:
                explanation = explainer.explain(report, job)
            except Exception as e:  # LLM is best-effort; never block on it
                log.exception("explainer failed")
                explanation = to_markdown(report) + f"\n\n_AI explanation unavailable: {type(e).__name__}_"
        else:
            explanation = None

        body = build_callback(job, report, passed, explanation)
    except Exception as e:  # noqa: BLE001 - fail closed but tell humans why
        log.exception("run task processing failed")
        body = {"data": {"type": "task-results", "attributes": {
            "status": "failed", "message": f"tf-risk-agent error: {type(e).__name__}: {str(e)[:150]}"}}}

    send_callback(job, body)
    return body
