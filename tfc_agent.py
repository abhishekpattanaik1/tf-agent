#!/usr/bin/env python3
"""
tfc_agent.py - OUTBOUND-ONLY AI reviewer for HCP Terraform runs.

Nothing calls into your network. This script calls out to:
  * app.terraform.io (+ HashiCorp's archivist storage for the plan JSON download)
  * your Azure OpenAI endpoint
It reads the plan, runs the deterministic scan, asks Azure OpenAI for the explanation
and posts it as a COMMENT on the TFC run, where the person applying will see it.
The blocking itself is done by the OPA policy set (policies/), which runs inside TFC.

Usage
  # one run: test from your laptop, prints the report, posts nothing
  python tfc_agent.py review --run run-AbC123
  python tfc_agent.py review --run run-AbC123 --post        # also post the comment

  # continuous: poll workspaces and review every new plan once
  python tfc_agent.py watch --org myorg --workspaces dbx-prod,sql-prod --interval 60 \
      --state-file /var/lib/tf-risk-agent/state.json

  # offline: no TFC at all, a plan.json you exported
  python tfc_agent.py file plan.json

Env
  TFC_TOKEN       team token with ADMIN on the target workspaces (TFC requires admin to read
                  plan JSON; org tokens are not accepted). Keep it in Key Vault.
  TFC_ADDRESS     default https://app.terraform.io
  AZURE_OPENAI_*  see explainer.py (omit to get the deterministic report only)
  PROD_WORKSPACE_REGEX  default: "prod" as a whole word (matches dbx-prod, not nonprod/preprod)
  TF_RISK_STATE   state file for `watch` (default ./.tf-risk-agent-state.json)
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import explainer
from runtask_core import fetch_plan_json
from tf_risk_scan import DEFAULT_PROD_RE, gate_decision, is_prod_workspace, scan, to_markdown

TFC = os.getenv("TFC_ADDRESS", "https://app.terraform.io").rstrip("/")
MARKER = "<!-- tf-risk-agent -->"
PRE_APPLY = ["planned", "cost_estimated", "policy_checked", "policy_override",
             "policy_soft_failed", "post_plan_completed", "planned_and_finished"]
# On auto-apply workspaces a run can move past "planned" between two polls. Still review it,
# so the run page keeps an audit trail of what was applied.
POST_APPLY = ["confirmed", "apply_queued", "applying", "applied"]
REVIEWABLE = PRE_APPLY + POST_APPLY
PROD_RE = os.getenv("PROD_WORKSPACE_REGEX", DEFAULT_PROD_RE)
PAGE_SIZE, MAX_PAGES = 20, 5
MAX_FAILURES = 3          # give up on a run after this many failed reviews (e.g. plan JSON gone)
STATE_KEEP = 500          # run IDs remembered per workspace


# --------------------------------------------------------------------------- TFC API
def api(method, path, body=None, retries=3):
    """TFC API call. Retries 429 (rate limit, honours Retry-After) and 5xx."""
    for attempt in range(retries + 1):
        req = urllib.request.Request(
            f"{TFC}/api/v2{path}", method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {os.environ['TFC_TOKEN']}",
                     "Content-Type": "application/vnd.api+json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            if attempt == retries or not (e.code == 429 or e.code >= 500):
                raise
            try:
                wait = float(e.headers.get("Retry-After") or 0)
            except ValueError:
                wait = 0
            time.sleep(min(max(wait, 2 ** attempt), 60))


def run_info(run_id):
    d = api("GET", f"/runs/{run_id}?include=workspace")
    ws = next((i for i in d.get("included", []) if i["type"] == "workspaces"), None)
    return {"run_id": run_id,
            "status": d["data"]["attributes"]["status"],
            "message": d["data"]["attributes"].get("message"),
            "workspace_name": ws["attributes"]["name"] if ws else None,
            "is_speculative": d["data"]["attributes"].get("plan-only", False)}


def already_reviewed(run_id):
    comments = api("GET", f"/runs/{run_id}/comments").get("data", [])
    return any(MARKER in (c["attributes"].get("body") or "") for c in comments)


def post_comment(run_id, markdown):
    api("POST", f"/runs/{run_id}/comments",
        {"data": {"type": "comments", "attributes": {"body": f"{MARKER}\n{markdown}"[:60000]}}})


def list_runs(workspace_id, max_pages=MAX_PAGES, known=frozenset()):
    """Reviewable runs, newest first. Stops after the first page that contains a run we have
    already handled: everything older was seen on an earlier poll."""
    runs = []
    for page in range(1, max_pages + 1):
        q = urllib.parse.urlencode({"filter[status]": ",".join(REVIEWABLE),
                                    "page[size]": PAGE_SIZE, "page[number]": page})
        d = api("GET", f"/workspaces/{workspace_id}/runs?{q}")
        data = d.get("data", [])
        runs.extend(data)
        nxt = (d.get("meta") or {}).get("pagination", {}).get("next-page")
        if not data or not nxt or any(r["id"] in known for r in data):
            break
    return runs


# --------------------------------------------------------------------------- state
class State:
    """Run IDs already handled, per workspace. Saves comments-API calls on every poll and
    survives restarts. The comment marker remains the source of truth if this file is lost."""

    def __init__(self, path):
        self.path = path
        self.reviewed = {}
        self.failures = {}
        if path and os.path.exists(path):
            try:
                with open(path) as fh:
                    self.reviewed = {k: list(v) for k, v in json.load(fh).get("reviewed", {}).items()}
            except (OSError, ValueError) as e:
                print(f"state file unreadable ({e}); starting fresh", file=sys.stderr)

    def known(self, ws_id):
        return set(self.reviewed.get(ws_id, []))

    def mark(self, ws_id, run_id):
        ids = [r for r in self.reviewed.get(ws_id, []) if r != run_id]
        self.reviewed[ws_id] = ([run_id] + ids)[:STATE_KEEP]

    def fail(self, ws_id, run_id):
        """Returns True when the run should be given up on."""
        n = self.failures.get(run_id, 0) + 1
        self.failures[run_id] = n
        if n >= MAX_FAILURES:
            self.mark(ws_id, run_id)
            return True
        return False

    def save(self):
        if not self.path:
            return
        tmp = f"{self.path}.tmp"
        with open(tmp, "w") as fh:
            json.dump({"reviewed": self.reviewed}, fh)
        os.replace(tmp, self.path)  # atomic: a crash never leaves a half-written file


# --------------------------------------------------------------------------- review
def analyse(plan, workspace_name, run_meta=None):
    prod = is_prod_workspace(workspace_name, PROD_RE)
    report = scan(plan, argparse.Namespace(prod_pattern=".*" if prod else DEFAULT_PROD_RE))
    report["workspace"], report["prod_workspace"] = workspace_name, prod
    report["gate"] = gate_decision(report)  # mirrors the OPA policy (critical destroy/replace)
    md = to_markdown(report)
    if report["findings"] and os.getenv("AZURE_OPENAI_ENDPOINT"):
        try:
            md += "\n\n---\n## 🤖 AI review (Azure OpenAI)\n\n" + explainer.explain(report, run_meta or {})
        except Exception as e:  # noqa: BLE001
            md += f"\n\n_AI review unavailable: {type(e).__name__}: {e}_"
    return report, md


def review_run(run_id, post=False, skip_if_done=False):
    if skip_if_done and already_reviewed(run_id):
        return None
    meta = run_info(run_id)
    plan = fetch_plan_json(f"{TFC}/api/v2/runs/{run_id}/plan/json-output", os.environ["TFC_TOKEN"])
    report, md = analyse(plan, meta["workspace_name"],
                         {"workspace_name": meta["workspace_name"], "run_message": meta["message"],
                          "is_speculative": meta["is_speculative"]})
    if meta["status"] in POST_APPLY:
        md = (f"> ⚠️ Reviewed after the apply had already started (status `{meta['status']}`), "
              "probably auto-apply. This comment is the audit record.\n\n" + md)
    if post:
        post_comment(run_id, md)
    return report, md


def workspace_id(org, name):
    return api("GET", f"/organizations/{urllib.parse.quote(org)}/workspaces/{urllib.parse.quote(name)}")["data"]["id"]


def poll_workspace(name, wid, state, post=True, log=print):
    """One poll of one workspace. Returns the run IDs reviewed this time."""
    known = state.known(wid)
    done = []
    for r in list_runs(wid, known=known):
        rid = r["id"]
        if rid in known:
            continue
        try:
            res = review_run(rid, post=post, skip_if_done=True)  # marker check guards a lost state file
            state.mark(wid, rid)
            if res:
                done.append(rid)
                crit = sum(f["severity"] == "critical" for f in res[0]["findings"])
                log(f"[{name}] reviewed {rid}: {len(res[0]['findings'])} findings, {crit} critical")
        except Exception as e:  # noqa: BLE001 - one bad run must not stop the others
            gave_up = state.fail(wid, rid)
            log(f"[{name}] {rid} failed: {type(e).__name__}: {e}" + (" (giving up)" if gave_up else ""))
    state.save()
    return done


def watch(org, workspaces, interval, state_file):
    ids = {w: workspace_id(org, w) for w in workspaces}
    state = State(state_file)
    print(f"watching {', '.join(workspaces)} every {interval}s (state: {state_file})", flush=True)
    while True:
        for name, wid in ids.items():
            try:
                poll_workspace(name, wid, state, log=lambda m: print(m, flush=True))
            except Exception as e:  # noqa: BLE001 - keep watching other workspaces
                print(f"[{name}] error: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        time.sleep(interval)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("review"); r.add_argument("--run", required=True); r.add_argument("--post", action="store_true")
    w = sub.add_parser("watch"); w.add_argument("--org", required=True)
    w.add_argument("--workspaces", required=True); w.add_argument("--interval", type=int, default=60)
    w.add_argument("--state-file", default=os.getenv("TF_RISK_STATE", ".tf-risk-agent-state.json"))
    f = sub.add_parser("file"); f.add_argument("plan_json"); f.add_argument("--workspace", default="")
    a = ap.parse_args()

    if a.cmd == "file":
        with open(a.plan_json) as fh:
            _, md = analyse(json.load(fh), a.workspace)
        print(md)
    elif a.cmd == "review":
        _, md = review_run(a.run, post=a.post)
        print(md)
        if a.post:
            print(f"\n(comment posted on {a.run})")
    else:
        watch(a.org, [x.strip() for x in a.workspaces.split(",") if x.strip()], a.interval, a.state_file)


if __name__ == "__main__":
    main()
