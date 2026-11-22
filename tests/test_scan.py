"""Unit tests for the deterministic layer.  Run:  python -m unittest discover -s tests -t ."""
import json
import os
import unittest
from argparse import Namespace

import gen_policy
import tf_risk_scan as s

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARGS = Namespace(prod_pattern=s.DEFAULT_PROD_RE)


def rc(address, rtype, actions, before=None, after=None, **extra):
    name = address.split(".")[-1].split("[")[0]
    return {"address": address, "mode": "managed", "type": rtype, "name": name,
            "change": {"actions": actions, "before": before, "after": after, **extra}}


class ProdRegex(unittest.TestCase):
    def test_workspaces(self):
        for name in ["prod", "dbx-prod", "dbx-platform-prod", "prod-eu", "sql_prod_01", "PROD", "production", "app-prod2"]:
            self.assertTrue(s.is_prod_workspace(name), name)
        for name in ["nonprod", "dbx-nonprod", "preprod", "pre-prod", "non_prod", "prodigy", "dev", ""]:
            self.assertFalse(s.is_prod_workspace(name), name)

    def test_addresses(self):
        self.assertTrue(s.is_prod("module.prod_data.azurerm_subnet.x", ARGS))
        self.assertTrue(s.is_prod('azurerm_subnet.x["prod"]', ARGS))
        self.assertFalse(s.is_prod("module.nonprod_data.azurerm_subnet.x", ARGS))


class CriticalTypes(unittest.TestCase):
    def test_exact_types_are_critical(self):
        for t in ["azurerm_mssql_database", "azurerm_subnet", "azurerm_databricks_workspace",
                  "azurerm_key_vault", "azurerm_key_vault_key", "databricks_cluster"]:
            self.assertTrue(s.is_critical_type(t), t)

    def test_children_are_not(self):
        for t in ["azurerm_mssql_firewall_rule", "azurerm_mssql_database_extended_auditing_policy",
                  "azurerm_key_vault_secret", "azurerm_key_vault_access_policy",
                  "databricks_workspace_conf", "databricks_workspace_file", "aws_elasticache_parameter_group"]:
            self.assertFalse(s.is_critical_type(t), t)

    def test_rego_is_in_sync(self):
        with open(os.path.join(ROOT, "policies", "block_destructive.rego")) as fh:
            self.assertEqual(fh.read(), gen_policy.render(),
                             "policies/ is stale: run `python gen_policy.py`")

    def test_no_char_classes(self):
        with self.assertRaises(ValueError):
            gen_policy.render(["aws_[a-z]*"])


class Actions(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(s.classify_action(["create", "delete"]), "replace")
        self.assertEqual(s.classify_action(["forget"]), "noop")
        self.assertEqual(s.classify_action(["read"]), "noop")

    def test_forget_is_not_a_finding(self):
        r = s.scan({"resource_changes": [rc("azurerm_mssql_database.a", "azurerm_mssql_database", ["forget"])]}, ARGS)
        self.assertEqual(r["findings"], [])


class ChangedPaths(unittest.TestCase):
    def test_unknown_is_not_a_change(self):
        changed, unknown = s.changed_paths({"id": "x", "subnet_id": "a", "tags": {"a": 1}},
                                           {"id": "x", "tags": {"a": 2}},
                                           {"subnet_id": True})
        self.assertEqual([s.fmt_path(p) for p in changed], ["tags.a"])
        self.assertEqual([s.fmt_path(p) for p in unknown], ["subnet_id"])

    def test_scan_reports_known_after_apply(self):
        plan = {"resource_changes": [rc("azurerm_private_endpoint.p", "azurerm_private_endpoint", ["update"],
                                        {"subnet_id": "a", "name": "p"}, {"name": "p"}, after_unknown={"subnet_id": True})]}
        f = s.scan(plan, ARGS)["findings"][0]
        self.assertEqual(f["changed_attributes"], [])
        self.assertEqual(f["known_after_apply"], ["subnet_id"])

    def test_deep_paths_collapse(self):
        changed, _ = s.changed_paths({"a": {"b": {"c": {"d": 1}}}}, {"a": {"b": {"c": {"d": 2}}}})
        self.assertEqual([s.fmt_path(p) for p in changed], ["a.b.c"])


class Moves(unittest.TestCase):
    def test_one_to_one_by_identity(self):
        rcs = [rc("azurerm_subnet.a", "azurerm_subnet", ["delete"], {"name": "snet-a"}),
               rc("azurerm_subnet.b", "azurerm_subnet", ["delete"], {"name": "snet-b"}),
               rc('module.net.azurerm_subnet.this["b"]', "azurerm_subnet", ["create"], None, {"name": "snet-b"}),
               rc('module.net.azurerm_subnet.this["a"]', "azurerm_subnet", ["create"], None, {"name": "snet-a"})]
        moves = {m["from"]: m for m in s.match_moves(rcs)}
        self.assertEqual(len(moves), 2)
        self.assertEqual(moves["azurerm_subnet.a"]["to"], 'module.net.azurerm_subnet.this["a"]')
        self.assertEqual(moves["azurerm_subnet.b"]["to"], 'module.net.azurerm_subnet.this["b"]')
        self.assertEqual(moves["azurerm_subnet.a"]["confidence"], "high")

    def test_types_must_match_and_replaces_excluded(self):
        rcs = [rc("azurerm_subnet.a", "azurerm_subnet", ["delete", "create"]),
               rc("azurerm_subnet.c", "azurerm_subnet", ["create"]),
               rc("azurerm_storage_account.x", "azurerm_storage_account", ["delete"]),
               rc("azurerm_storage_container.x", "azurerm_storage_container", ["create"])]
        self.assertEqual(s.match_moves(rcs), [])

    def test_more_creates_than_deletes(self):
        rcs = [rc("azurerm_subnet.old", "azurerm_subnet", ["delete"], {"name": "x"}),
               rc("azurerm_subnet.new", "azurerm_subnet", ["create"], None, {"name": "x"}),
               rc("azurerm_subnet.other", "azurerm_subnet", ["create"], None, {"name": "y"})]
        f = s.scan({"resource_changes": rcs}, ARGS)["findings"][0]
        self.assertEqual(f["possible_move_to"], ["azurerm_subnet.new"])

    def test_values_never_emitted(self):
        rcs = [rc("azurerm_mssql_database.a", "azurerm_mssql_database", ["delete"], {"name": "SECRET-NAME"}),
               rc("module.m.azurerm_mssql_database.a", "azurerm_mssql_database", ["create"], None, {"name": "SECRET-NAME"})]
        r = s.scan({"resource_changes": rcs}, ARGS)
        self.assertNotIn("SECRET-NAME", json.dumps(r) + s.to_markdown(r))


class Gate(unittest.TestCase):
    def test_gate(self):
        crit = {"findings": [{"severity": "critical"}]}
        high = {"findings": [{"severity": "high"}]}
        self.assertEqual(s.gate_decision(crit), "BLOCKED")
        self.assertEqual(s.gate_decision(high), "PASS")
        self.assertEqual(s.gate_decision(high, "high"), "BLOCKED")


class SamplePlan(unittest.TestCase):
    def test_sample_end_to_end(self):
        with open(os.path.join(ROOT, "sample_plan.json")) as fh:
            r = s.scan(json.load(fh), Namespace(prod_pattern=".*"))
        self.assertEqual(sum(f["severity"] == "critical" for f in r["findings"]), 3)
        self.assertEqual(r["graph_sources"], ["configuration", "prior_state"])
        self.assertEqual(r["moved_blocks"][0]["to"], "module.sql.azurerm_mssql_database.orders")
        md = s.to_markdown(r)
        self.assertIn("Blast radius", md)
        self.assertNotIn("10.0.1.0/24", md)


if __name__ == "__main__":
    unittest.main()
