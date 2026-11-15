#!/usr/bin/env python3
"""
tf_risk_scan.py - deterministic risk scanner for Terraform plans.

Catches the changes humans miss in long plans: destroys, replacements
(delete+create), and risky in-place updates on stateful / critical resources.
No LLM involved - this is the fact layer. Its JSON output feeds the LLM
explainer stage; its Markdown output can be posted as a PR comment.

Usage:
    terraform plan -out=tfplan
    terraform show -json tfplan > plan.json
    python tf_risk_scan.py plan.json --md report.md --json findings.json --fail-on critical

Exit codes: 0 = OK, 2 = findings at/above --fail-on severity, 1 = error.
Values are never printed - only resource addresses and attribute paths -
so the output is safe to send to an LLM or post on a PR.
"""
import argparse
import fnmatch
import json
import re
import sys
from collections import defaultdict

# ---------------------------------------------------------------------------
# Resource types whose destruction loses data, breaks dependents, or causes
# outage. Extend this list for your estate (glob patterns allowed).
# ---------------------------------------------------------------------------
CRITICAL_TYPES = [
    # Databricks
    "databricks_mws_workspaces", "databricks_workspace*", "databricks_metastore*",
    "databricks_catalog", "databricks_schema", "databricks_external_location",
    "databricks_storage_credential", "databricks_cluster", "databricks_instance_pool",
    "databricks_sql_endpoint", "databricks_job", "databricks_mws_networks",
    "databricks_mws_private_access_settings",
    "azurerm_databricks_workspace*",
    # Databases
    "aws_db_instance", "aws_rds_cluster*", "aws_dynamodb_table", "aws_elasticache_*",
    "aws_redshift_cluster", "azurerm_mssql_*", "azurerm_postgresql*", "azurerm_mysql*",
    "azurerm_cosmosdb_*", "google_sql_database*", "google_bigquery_dataset",
    "snowflake_database", "snowflake_schema",
    # Storage / keys
    "aws_s3_bucket", "aws_efs_file_system", "aws_kms_key", "azurerm_storage_account",
    "azurerm_storage_container", "azurerm_key_vault*", "google_storage_bucket",
    "google_kms_*",
    # Network (recreate = outage / IP churn / workspace breakage)
    "aws_vpc", "aws_subnet", "aws_nat_gateway", "aws_vpc_endpoint", "aws_route_table",
    "azurerm_virtual_network", "azurerm_subnet", "azurerm_private_endpoint",
    "azurerm_network_security_group", "google_compute_network", "google_compute_subnetwork",
]

# Updates (not just replaces) worth flagging - permission / exposure changes.
SENSITIVE_UPDATE_TYPES = [
    "aws_iam_*", "aws_security_group*", "azurerm_role_assignment",
    "azurerm_network_security_rule", "google_*_iam_*", "databricks_permissions",
    "databricks_grants", "databricks_cluster_policy", "databricks_secret_acl",
]

REASON_HINTS = {
    "replace_because_cannot_update": "An attribute that can't be updated in place changed (see 'forced by').",
    "replace_because_tainted": "The resource is tainted. Check whether someone ran `terraform taint` or a previous apply failed.",
    "replace_by_request": "Replacement was requested explicitly (-replace=...).",
    "replace_by_triggers": "A replace_triggered_by dependency changed.",
    "delete_because_no_resource_config": "The resource was removed from config. If it was moved or renamed, add a `moved {}` block.",
    "delete_because_no_module": "Its module was removed or renamed. If it was renamed, add a `moved {}` block.",
    "delete_because_count_index": "The count index shifted. Classic list-reorder bug; switch to for_each with stable keys.",
    "delete_because_each_key": "The for_each key no longer exists. If the key was renamed, add a `moved {}` block.",
    "delete_because_wrong_repetition": "Switched between count / for_each / single. Needs `moved {}` blocks.",
}

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def matches(rtype, patterns):
    return any(fnmatch.fnmatch(rtype, p) for p in patterns)


def classify_action(actions):
    a = list(actions)
    if a in (["delete", "create"], ["create", "delete"]):
        return "replace"
    if a == ["delete"]:
        return "delete"
    if a == ["update"]:
        return "update"
    if a == ["create"]:
        return "create"
    return "noop"  # no-op, read, forget


def is_prod(address, args):
    return bool(args.prod_pattern and re.search(args.prod_pattern, address, re.I))


def severity(kind, rtype, address, args):
    critical = matches(rtype, CRITICAL_TYPES)
    if kind in ("replace", "delete"):
        sev = "critical" if critical else "high"
    elif kind == "update" and (critical or matches(rtype, SENSITIVE_UPDATE_TYPES)):
        sev = "medium"
    else:
        return None
    # Prod raises sensitive updates one level; it does NOT turn non-critical replaces
    # into blockers (keeps the gate signal high, so people don't learn to override).
    if is_prod(address, args) and sev == "medium":
        sev = "high"
    return sev


def fmt_path(p):
    return ".".join(str(x) for x in p)


def changed_paths(before, after, prefix=()):
    """Top-level-ish attribute paths that differ (values are not returned)."""
    out = []
    if isinstance(before, dict) and isinstance(after, dict):
        for k in sorted(set(before) | set(after)):
            if before.get(k) != after.get(k):
                sub = changed_paths(before.get(k), after.get(k), prefix + (k,))
                out.extend(sub if sub and len(prefix) < 2 else [prefix + (k,)])
    elif before != after:
        out.append(prefix)
    return out


def scan(plan, args):
    findings = []
    deletes, creates = defaultdict(list), defaultdict(list)

    for rc in plan.get("resource_changes", []):
        if rc.get("mode") == "data":
            continue
        ch = rc.get("change", {})
        kind = classify_action(ch.get("actions", []))
        rtype, addr = rc["type"], rc["address"]

        if kind in ("delete", "replace"):
            deletes[rtype].append(addr)
        if kind == "create":
            creates[rtype].append(addr)

        sev = severity(kind, rtype, addr, args)
        if not sev:
            continue
        reason = rc.get("action_reason", "")
        f = {
            "severity": sev,
            "action": kind,
            "address": addr,
            "type": rtype,
            "action_reason": reason,
            "hint": REASON_HINTS.get(reason, ""),
            "forced_by": [fmt_path(p) for p in ch.get("replace_paths", []) or []],
            "changed_attributes": [],
            "prod": is_prod(addr, args),
        }
        if kind == "update":
            f["changed_attributes"] = [
                fmt_path(p) for p in changed_paths(ch.get("before"), ch.get("after"))
            ][:15]
        findings.append(f)

    # Possible renames: same type deleted at one address and created at another.
    move_suggestions = []
    for rtype, dels in deletes.items():
        for d in dels:
            for c in creates.get(rtype, []):
                move_suggestions.append({"type": rtype, "from": d, "to": c})
    for f in findings:
        if f["action"] == "delete":
            cands = [m["to"] for m in move_suggestions if m["from"] == f["address"]]
            if cands:
                f["possible_move_to"] = cands
                f["hint"] = (f["hint"] + " " if f["hint"] else "") + \
                    "A same-type resource is being created elsewhere, which may be a rename. " \
                    f"Consider `moved {{ from = {f['address']}  to = {cands[0]} }}`."

    drift = [
        {"address": d["address"], "actions": d.get("change", {}).get("actions", [])}
        for d in plan.get("resource_drift", [])
    ]

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["address"]))
    counts = defaultdict(int)
    for rc in plan.get("resource_changes", []):
        counts[classify_action(rc.get("change", {}).get("actions", []))] += 1

    return {
        "terraform_version": plan.get("terraform_version"),
        "summary": {k: counts[k] for k in ("create", "update", "replace", "delete")},
        "findings": findings,
        "drift": drift,
    }


ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}


def to_markdown(r):
    s = r["summary"]
    lines = ["## Terraform change risk report", "",
             f"**Plan:** {s['create']} to create · {s['update']} to update · "
             f"**{s['replace']} to replace** · **{s['delete']} to destroy**", ""]
    crit = [f for f in r["findings"] if f["severity"] == "critical"]
    if crit:
        lines += [f"> ⛔ **{len(crit)} critical change(s)**. Needs explicit owner approval before apply.", ""]
    elif not r["findings"]:
        lines += ["✅ No destructive or sensitive changes detected.", ""]
    if r["findings"]:
        lines += ["| Sev | Action | Resource | Why |", "|---|---|---|---|"]
        for f in r["findings"]:
            why = []
            if f["forced_by"]:
                why.append("forced by `" + "`, `".join(f["forced_by"]) + "`")
            if f["changed_attributes"]:
                why.append("changes `" + "`, `".join(f["changed_attributes"][:5]) + "`")
            if f["hint"]:
                why.append(f["hint"])
            lines.append(f"| {ICON[f['severity']]} {f['severity']} | {f['action']} | "
                         f"`{f['address']}` | {' '.join(why) or '-'} |")
        lines.append("")
    if r["drift"]:
        lines += [f"**Drift detected outside Terraform ({len(r['drift'])}):** " +
                  ", ".join(f"`{d['address']}`" for d in r["drift"][:10]), ""]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("plan_json")
    ap.add_argument("--md", help="write Markdown report (PR comment)")
    ap.add_argument("--json", help="write findings JSON (input for LLM stage)")
    ap.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="critical")
    ap.add_argument("--prod-pattern", default=r"(^|[._\[\"-])prod",
                    help="regex on resource address that marks prod (escalates severity)")
    args = ap.parse_args()

    try:
        with open(args.plan_json) as fh:
            plan = json.load(fh)
    except Exception as e:  # noqa: BLE001
        print(f"error reading plan: {e}", file=sys.stderr)
        return 1

    report = scan(plan, args)
    md = to_markdown(report)
    if args.md:
        open(args.md, "w").write(md)
    if args.json:
        json.dump(report, open(args.json, "w"), indent=2)
    print(md)

    threshold = SEVERITY_ORDER[args.fail_on]
    return 2 if any(SEVERITY_ORDER[f["severity"]] >= threshold for f in report["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
