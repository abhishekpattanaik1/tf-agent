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
so the output is safe to send to an LLM or post on a PR. (Values ARE compared
locally, e.g. to match a deleted resource to its renamed twin, but never emitted.)
"""
import argparse
import difflib
import fnmatch
import json
import re
import sys
from collections import defaultdict

import blast_radius

# ---------------------------------------------------------------------------
# Resource types whose destruction loses data, breaks dependents, or causes
# outage. Extend this list for your estate. Prefer EXACT type names: a broad glob
# such as "azurerm_mssql_*" also matches firewall rules and auditing policies, and
# every false block teaches people to click Override. Globs are still supported
# (Python fnmatch here, OPA glob.match in the gate), but avoid [] character classes.
# ---------------------------------------------------------------------------
CRITICAL_TYPES = [
    # Databricks (workspace recreate = new workspace ID/URL; everything inside is lost)
    "databricks_mws_workspaces", "databricks_mws_networks", "databricks_mws_private_access_settings",
    "databricks_mws_storage_configurations", "databricks_metastore", "databricks_metastore_assignment",
    "databricks_metastore_data_access", "databricks_catalog", "databricks_schema", "databricks_volume",
    "databricks_external_location", "databricks_storage_credential", "databricks_cluster",
    "databricks_instance_pool", "databricks_sql_endpoint", "databricks_job",
    "azurerm_databricks_workspace", "azurerm_databricks_access_connector",
    # Databases
    "aws_db_instance", "aws_rds_cluster", "aws_rds_cluster_instance", "aws_dynamodb_table",
    "aws_elasticache_cluster", "aws_elasticache_replication_group", "aws_redshift_cluster",
    "azurerm_mssql_server", "azurerm_mssql_database", "azurerm_mssql_elasticpool",
    "azurerm_mssql_managed_instance", "azurerm_mssql_managed_database",
    "azurerm_postgresql_server", "azurerm_postgresql_database",
    "azurerm_postgresql_flexible_server", "azurerm_postgresql_flexible_server_database",
    "azurerm_mysql_server", "azurerm_mysql_database",
    "azurerm_mysql_flexible_server", "azurerm_mysql_flexible_database",
    "azurerm_cosmosdb_account", "azurerm_cosmosdb_sql_database", "azurerm_cosmosdb_sql_container",
    "azurerm_cosmosdb_mongo_database", "azurerm_cosmosdb_mongo_collection",
    "azurerm_cosmosdb_cassandra_keyspace", "azurerm_cosmosdb_gremlin_database", "azurerm_cosmosdb_table",
    "azurerm_cosmosdb_postgresql_cluster",
    "google_sql_database_instance", "google_sql_database", "google_bigquery_dataset",
    "google_bigquery_table", "snowflake_database", "snowflake_schema",
    # Storage / keys (key destroy = CMK-encrypted data unreadable)
    "aws_s3_bucket", "aws_efs_file_system", "aws_kms_key",
    "azurerm_storage_account", "azurerm_storage_container", "azurerm_storage_share",
    "azurerm_storage_data_lake_gen2_filesystem", "azurerm_key_vault", "azurerm_key_vault_key",
    "azurerm_key_vault_managed_hardware_security_module",
    "google_storage_bucket", "google_kms_key_ring", "google_kms_crypto_key",
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

# "prod" as a whole word: matches prod, dbx-prod, prod-eu, production, module.prod_data,
# but NOT nonprod, preprod, pre-prod, non_prod or prodigy.
DEFAULT_PROD_RE = r"(?<![a-z])(?<!pre[-_.])(?<!non[-_.])prod(uction)?(?![a-z])"

# Attributes that identify the real-world object. Used only to pair a deleted resource
# with a created one (possible rename); compared locally, never emitted.
IDENTITY_ATTRS = ("name", "identifier", "cluster_name", "bucket", "display_name",
                  "database_name", "workspace_name", "account_name")


def matches(rtype, patterns):
    # fnmatchcase: same semantics on every OS, like OPA's glob.match
    return any(fnmatch.fnmatchcase(rtype, p) for p in patterns)


def is_critical_type(rtype):
    return matches(rtype, CRITICAL_TYPES)


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


def is_prod_workspace(name, pattern=None):
    return bool(re.search(pattern or DEFAULT_PROD_RE, name or "", re.I))


def severity(kind, rtype, address, args):
    critical = is_critical_type(rtype)
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


def _has_unknown(u):
    if u is True:
        return True
    if isinstance(u, dict):
        return any(_has_unknown(v) for v in u.values())
    if isinstance(u, list):
        return any(_has_unknown(v) for v in u)
    return False


def changed_paths(before, after, unknown=None, prefix=()):
    """Attribute paths that differ, split into (changed, known_after_apply).
    A path whose new value is unknown until apply shows as null in `after`; it is
    reported as known-after-apply instead of as a change. Values are never returned."""
    if unknown is True:
        return [], [prefix]
    if isinstance(before, dict) and isinstance(after, dict):
        changed, unk = [], []
        u = unknown if isinstance(unknown, dict) else {}
        for k in sorted(set(before) | set(after) | set(u)):
            sub_u = u.get(k)
            if before.get(k) == after.get(k) and not _has_unknown(sub_u):
                continue
            c, n = changed_paths(before.get(k), after.get(k), sub_u, prefix + (k,))
            if len(prefix) >= 2:  # keep paths short: collapse below depth 3
                c, n = ([prefix + (k,)] if c else []), ([prefix + (k,)] if n and not c else [])
            changed += c
            unk += n
        return changed, unk
    if _has_unknown(unknown):
        return [], [prefix]
    return ([prefix] if before != after else []), []


# --------------------------------------------------------------------------- renames
def _base(address):
    """module.a.aws_x.y[0] -> ('module.a', 'y')"""
    parts = blast_radius.strip_keys(address).split(".")
    return ".".join(parts[:-2]), parts[-1]


def move_score(deleted_rc, created_rc):
    """How likely `created` is `deleted` under a new address. Same type is a precondition."""
    score = 0.0
    before = (deleted_rc.get("change") or {}).get("before") or {}
    after = (created_rc.get("change") or {}).get("after") or {}
    if any(before.get(a) is not None and before.get(a) == after.get(a) for a in IDENTITY_ATTRS):
        score += 3  # same real-world name: strongest signal
    (dmod, dname), (cmod, cname) = _base(deleted_rc["address"]), _base(created_rc["address"])
    if dname == cname:
        score += 2  # moved into / out of a module
    if dmod == cmod:
        score += 0.5  # renamed in place
    score += difflib.SequenceMatcher(None, deleted_rc["address"], created_rc["address"]).ratio()
    return score


def match_moves(rcs):
    """One-to-one pairing of deleted -> created resources of the same type, best score first.
    Replaces are excluded: they keep their address, so a `moved` block can't help them."""
    deleted = [rc for rc in rcs if classify_action(rc.get("change", {}).get("actions", [])) == "delete"]
    created = [rc for rc in rcs if classify_action(rc.get("change", {}).get("actions", [])) == "create"]
    pairs = [(move_score(d, c), d["address"], c["address"])
             for d in deleted for c in created if d["type"] == c["type"]]
    pairs.sort(key=lambda p: (-p[0], p[1], p[2]))
    used_from, used_to, moves = set(), set(), []
    for score, frm, to in pairs:
        if frm in used_from or to in used_to:
            continue
        used_from.add(frm)
        used_to.add(to)
        moves.append({"from": frm, "to": to,
                      "confidence": "high" if score >= 3 else "medium" if score >= 2 else "low"})
    return moves


# --------------------------------------------------------------------------- scan
def scan(plan, args):
    findings = []
    rcs = [rc for rc in plan.get("resource_changes", []) if rc.get("mode") != "data"]

    for rc in rcs:
        ch = rc.get("change", {})
        kind = classify_action(ch.get("actions", []))
        rtype, addr = rc["type"], rc["address"]
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
            changed, unknown = changed_paths(ch.get("before"), ch.get("after"), ch.get("after_unknown"))
            f["changed_attributes"] = [fmt_path(p) for p in changed][:15]
            if unknown:
                f["known_after_apply"] = [fmt_path(p) for p in unknown][:10]
        findings.append(f)

    moves = match_moves(rcs)
    by_from = {m["from"]: m for m in moves}
    for f in findings:
        m = by_from.get(f["address"])
        if m:
            f["possible_move_to"] = [m["to"]]
            f["move_confidence"] = m["confidence"]
            f["hint"] = (f["hint"] + " " if f["hint"] else "") + \
                f"A same-type resource is being created at `{m['to']}` ({m['confidence']} confidence it is a rename). " \
                f"Consider `moved {{ from = {f['address']}  to = {m['to']} }}`."

    # Blast radius for everything being destroyed or replaced
    destructive = [f["address"] for f in findings if f["action"] in ("delete", "replace")]
    br = blast_radius.analyse(plan, destructive, is_critical_type)
    for f in findings:
        if f["address"] in br["by_address"]:
            f["blast_radius"] = br["by_address"][f["address"]]

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
        "moved_blocks": moves,
        "graph_sources": br["sources"],
        "drift": drift,
    }


def gate_decision(report, fail_on="critical"):
    """Mirrors the OPA gate (critical findings only arise from destroy/replace of a
    CRITICAL_TYPES resource). Given to the LLM so its verdict can't contradict the gate."""
    threshold = SEVERITY_ORDER[fail_on]
    blocked = any(SEVERITY_ORDER[f["severity"]] >= threshold for f in report["findings"])
    return "BLOCKED" if blocked else "PASS"


ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}


def _blast_line(f):
    b = f.get("blast_radius") or {}
    if not b.get("total"):
        return None
    names = [d["address"] for d in b.get("direct", [])] + b.get("indirect", [])
    shown = ", ".join(f"`{n}`" for n in names[:6])
    more = b["total"] - min(len(names), 6)
    line = f"- `{f['address']}` → **{b['total']} dependent resource(s)**"
    if b.get("critical_dependents"):
        line += f", **{len(b['critical_dependents'])} critical**"
    line += f": {shown}" + (f" (+{more} more)" if more > 0 else "")
    if b.get("also_changing"):
        line += f". {len(b['also_changing'])} of them also change in this plan"
    return line


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
            if f.get("known_after_apply"):
                why.append("known after apply: `" + "`, `".join(f["known_after_apply"][:5]) + "`")
            if f["hint"]:
                why.append(f["hint"])
            lines.append(f"| {ICON[f['severity']]} {f['severity']} | {f['action']} | "
                         f"`{f['address']}` | {' '.join(why) or '-'} |")
        lines.append("")
    blast = [x for x in (_blast_line(f) for f in r["findings"]) if x]
    if blast:
        lines += ["### 💥 Blast radius", *blast, "",
                  f"_From the Terraform dependency graph ({' + '.join(r.get('graph_sources') or ['none'])}). "
                  "Things that depend on these resources outside Terraform are not visible here._", ""]
    elif any(f["action"] in ("delete", "replace") for f in r["findings"]) and not r.get("graph_sources"):
        lines += ["_Blast radius unavailable: the plan JSON has no configuration or prior_state._", ""]
    if r.get("moved_blocks"):
        lines += ["### Suggested `moved` blocks (check before using)", "```hcl"]
        for m in r["moved_blocks"]:
            lines += [f"moved {{  # {m['confidence']} confidence",
                      f"  from = {m['from']}", f"  to   = {m['to']}", "}"]
        lines += ["```", ""]
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
    ap.add_argument("--prod-pattern", default=DEFAULT_PROD_RE,
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
        with open(args.md, "w") as fh:
            fh.write(md)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(report, fh, indent=2)
    print(md)
    return 2 if gate_decision(report, args.fail_on) == "BLOCKED" else 0


if __name__ == "__main__":
    sys.exit(main())
