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
  python tfc_agent.py watch --org myorg --workspaces dbx-prod,sql-prod --interval 60

  # offline: no TFC at all, a plan.json you exported
  python tfc_agent.py file plan.json

Env
  TFC_TOKEN       team token with ADMIN on the target workspaces (TFC requires admin to read
                  plan JSON; org tokens are not accepted). Keep it in Key Vault.
  TFC_ADDRESS     default https://app.terraform.io
  AZURE_OPENAI_*  see explainer.py (omit to get the deterministic report only)
  PROD_WORKSPACE_REGEX  default "prod"
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from types import SimpleNamespace

import explainer
from runtask_core import fetch_plan_json
from tf_risk_scan import scan, to_markdown

TFC = os.getenv("TFC_ADDRESS", "https://app.terraform.io").rstrip("/")
MARKER = "<!-- tf-risk-agent -->"
REVIEWABLE = ["planned", "cost_estimated", "policy_checked", "policy_override",
              "policy_soft_failed", "post_plan_completed", "planned_and_finished"]
PROD_RE = os.getenv("PROD_WORKSPACE_REGEX", "prod")


# --------------------------------------------------------------------------- TFC API
def api(method, path, body=None):
    req = urllib.request.Request(
        f"{TFC}/api/v2{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {os.environ['TFC_TOKEN']}",
                 "Content-Type": "application/vnd.api+json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}


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


# --------------------------------------------------------------------------- review
def analyse(plan, workspace_name, run_meta=None):
    prod = bool(re.search(PROD_RE, workspace_name or "", re.I))
    report = scan(plan, SimpleNamespace(prod_pattern=".*" if prod else r"(^|[._\[\"-])prod"))
    report["workspace"], report["prod_workspace"] = workspace_name, prod
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
    if post:
        post_comment(run_id, md)
    return report, md


def workspace_id(org, name):
    return api("GET", f"/organizations/{urllib.parse.quote(org)}/workspaces/{urllib.parse.quote(name)}")["data"]["id"]


def watch(org, workspaces, interval):
    ids = {w: workspace_id(org, w) for w in workspaces}
    print(f"watching {', '.join(workspaces)} every {interval}s", flush=True)
    while True:
        for name, wid in ids.items():
            try:
                q = urllib.parse.urlencode({"filter[status]": ",".join(REVIEWABLE), "page[size]": 10})
                for r in api("GET", f"/workspaces/{wid}/runs?{q}").get("data", []):
                    res = review_run(r["id"], post=True, skip_if_done=True)  # comment marker = idempotent
                    if res:
                        crit = sum(f["severity"] == "critical" for f in res[0]["findings"])
                        print(f"[{name}] reviewed {r['id']}: {len(res[0]['findings'])} findings, {crit} critical", flush=True)
            except Exception as e:  # noqa: BLE001 - keep watching other workspaces
                print(f"[{name}] error: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        time.sleep(interval)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("review"); r.add_argument("--run", required=True); r.add_argument("--post", action="store_true")
    w = sub.add_parser("watch"); w.add_argument("--org", required=True)
    w.add_argument("--workspaces", required=True); w.add_argument("--interval", type=int, default=60)
    f = sub.add_parser("file"); f.add_argument("plan_json"); f.add_argument("--workspace", default="")
    a = ap.parse_args()

    if a.cmd == "file":
        _, md = analyse(json.load(open(a.plan_json)), a.workspace)
        print(md)
    elif a.cmd == "review":
        _, md = review_run(a.run, post=a.post)
        print(md)
        if a.post:
            print(f"\n(comment posted on {a.run})")
    else:
        watch(a.org, [x.strip() for x in a.workspaces.split(",") if x.strip()], a.interval)


if __name__ == "__main__":
    main()
