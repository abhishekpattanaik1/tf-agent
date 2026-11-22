"""Unit tests for blast_radius.py.  Run:  python -m unittest discover -s tests -t ."""
import json
import os
import unittest

import blast_radius as br
from tf_risk_scan import is_critical_type

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def res(address, refs=(), depends_on=(), provider="azurerm", **extra):
    t, n = address.split(".")[-2:] if not address.startswith("data.") else address.split(".")[1:3]
    r = {"address": address, "mode": "data" if address.startswith("data.") else "managed",
         "type": t, "name": n, "provider_config_key": provider,
         "expressions": {"x": {"references": list(refs)}} if refs else {}}
    if depends_on:
        r["depends_on"] = list(depends_on)
    r.update(extra)
    return r


def plan(root_module, provider_config=None, state=None, changes=()):
    p = {"configuration": {"root_module": root_module, "provider_config": provider_config or {}},
         "resource_changes": list(changes)}
    if state:
        p["prior_state"] = {"values": {"root_module": state}}
    return p


class Helpers(unittest.TestCase):
    def test_strip_keys(self):
        self.assertEqual(br.strip_keys('module.a["x.y]"].aws_s3_bucket.b[0]'), "module.a.aws_s3_bucket.b")

    def test_node_type(self):
        self.assertEqual(br.node_type("module.a.module.b.azurerm_subnet.x"), "azurerm_subnet")
        self.assertEqual(br.node_type("module.a.data.azurerm_client_config.c"), "azurerm_client_config")
        self.assertTrue(br.is_data("module.a.data.azurerm_client_config.c"))
        self.assertFalse(br.is_data("module.data.azurerm_subnet.x"))


class Edges(unittest.TestCase):
    def radius(self, p, target):
        return br.analyse(p, [target], is_critical_type)["by_address"][target]

    def test_direct_and_transitive(self):
        p = plan({"resources": [res("azurerm_subnet.s"),
                                res("azurerm_private_endpoint.pe", ["azurerm_subnet.s.id", "azurerm_subnet.s"]),
                                res("azurerm_private_dns_a_record.r", ["azurerm_private_endpoint.pe"])]})
        r = self.radius(p, "azurerm_subnet.s")
        self.assertEqual(r["total"], 2)
        self.assertEqual(r["direct"], [{"address": "azurerm_private_endpoint.pe", "via": "reference"}])
        self.assertEqual(r["indirect"], ["azurerm_private_dns_a_record.r"])
        self.assertEqual(r["critical_dependents"], ["azurerm_private_endpoint.pe"])

    def test_module_input_and_output(self):
        child = {"resources": [res("azurerm_subnet.s", ["var.vnet"])],
                 "outputs": {"subnet_id": {"expression": {"references": ["azurerm_subnet.s.id", "azurerm_subnet.s"]}}}}
        p = plan({"resources": [res("azurerm_virtual_network.v"),
                                res("azurerm_network_interface.nic", ["module.net.subnet_id", "module.net"])],
                  "module_calls": {"net": {"module": child,
                                           "expressions": {"vnet": {"references": ["azurerm_virtual_network.v.name", "azurerm_virtual_network.v"]}}}}})
        self.assertEqual(self.radius(p, "azurerm_virtual_network.v")["total"], 2)  # subnet, then nic
        r = self.radius(p, "module.net.azurerm_subnet.s")
        self.assertEqual([d["address"] for d in r["direct"]], ["azurerm_network_interface.nic"])

    def test_bare_module_ref_does_not_pull_whole_module(self):
        child = {"resources": [res("azurerm_subnet.a"), res("azurerm_subnet.b")],
                 "outputs": {"a_id": {"expression": {"references": ["azurerm_subnet.a.id", "azurerm_subnet.a"]}}}}
        p = plan({"resources": [res("azurerm_network_interface.nic", ["module.net.a_id", "module.net"])],
                  "module_calls": {"net": {"module": child}}})
        self.assertEqual(self.radius(p, "module.net.azurerm_subnet.b")["total"], 0)
        self.assertEqual(self.radius(p, "module.net.azurerm_subnet.a")["total"], 1)

    def test_depends_on_whole_module(self):
        child = {"resources": [res("azurerm_subnet.a"), res("azurerm_subnet.b")]}
        p = plan({"resources": [res("azurerm_linux_virtual_machine.vm", depends_on=["module.net"])],
                  "module_calls": {"net": {"module": child}}})
        self.assertEqual(self.radius(p, "module.net.azurerm_subnet.b")["direct"],
                         [{"address": "azurerm_linux_virtual_machine.vm", "via": "depends_on"}])

    def test_module_call_depends_on_and_for_each(self):
        child = {"resources": [res("azurerm_storage_container.c")]}
        p = plan({"resources": [res("azurerm_storage_account.sa"), res("azurerm_resource_group.rg")],
                  "module_calls": {"data": {"module": child, "depends_on": ["azurerm_storage_account.sa"],
                                            "for_each_expression": {"references": ["azurerm_resource_group.rg"]}}}})
        self.assertEqual(self.radius(p, "azurerm_storage_account.sa")["direct"][0],
                         {"address": "module.data.azurerm_storage_container.c", "via": "module dependency"})
        self.assertEqual(self.radius(p, "azurerm_resource_group.rg")["total"], 1)

    def test_provider_config_edge(self):
        p = plan({"resources": [res("azurerm_databricks_workspace.w"),
                                res("databricks_cluster.c", provider="databricks"),
                                res("databricks_job.j", ["databricks_cluster.c.id"], provider="databricks")]},
                 provider_config={"databricks": {"name": "databricks", "expressions": {
                     "host": {"references": ["azurerm_databricks_workspace.w.workspace_url", "azurerm_databricks_workspace.w"]}}}})
        r = self.radius(p, "azurerm_databricks_workspace.w")
        self.assertEqual(r["total"], 2)
        self.assertEqual({d["via"] for d in r["direct"]}, {"provider config"})

    def test_through_data_source_counts_as_direct(self):
        p = plan({"resources": [res("azurerm_subnet.s"),
                                res("data.azurerm_subnet.lookup", depends_on=["azurerm_subnet.s"]),
                                res("azurerm_network_interface.nic", ["data.azurerm_subnet.lookup.id"])]})
        r = self.radius(p, "azurerm_subnet.s")
        self.assertEqual(r["total"], 1)  # data source traversed, not reported
        self.assertEqual([d["address"] for d in r["direct"]], ["azurerm_network_interface.nic"])

    def test_state_depends_on_covers_locals(self):
        p = plan({"resources": [res("azurerm_subnet.s"), res("azurerm_network_interface.nic")]},
                 state={"resources": [{"address": "azurerm_network_interface.nic[0]",
                                       "depends_on": ["azurerm_subnet.s"]}]})
        self.assertEqual(self.radius(p, "azurerm_subnet.s")["direct"],
                         [{"address": "azurerm_network_interface.nic", "via": "state depends_on"}])

    def test_also_changing_and_instance_keys(self):
        p = plan({"resources": [res("azurerm_subnet.s"),
                                res("azurerm_network_interface.nic", ["azurerm_subnet.s[0].id"])]},
                 changes=[{"address": "azurerm_network_interface.nic[\"a\"]", "change": {"actions": ["delete", "create"]}}])
        r = self.radius(p, "azurerm_subnet.s[0]")
        self.assertEqual(r["also_changing"], [{"address": "azurerm_network_interface.nic", "action": "replace"}])

    def test_cycle_is_safe(self):
        child = {"resources": [res("azurerm_subnet.s", ["var.x"])],
                 "outputs": {"o": {"expression": {"references": ["var.x"]}}}}
        p = plan({"module_calls": {"m": {"module": child,
                                         "expressions": {"x": {"references": ["module.m.o"]}}}}})
        self.assertEqual(self.radius(p, "module.m.azurerm_subnet.s")["total"], 0)

    def test_no_graph(self):
        r = br.analyse({"resource_changes": []}, ["azurerm_subnet.s"])
        self.assertEqual(r["sources"], [])
        self.assertEqual(r["by_address"]["azurerm_subnet.s"], {"total": 0})


class Sample(unittest.TestCase):
    def test_subnet_radius(self):
        with open(os.path.join(ROOT, "sample_plan.json")) as fh:
            p = json.load(fh)
        t = "module.prod_data.azurerm_subnet.dbx_private"
        r = br.analyse(p, [t], is_critical_type)["by_address"][t]
        names = {d["address"] for d in r["direct"]} | set(r["indirect"])
        self.assertEqual(names, {
            "module.prod_data.azurerm_databricks_workspace.this", "module.prod_data.azurerm_private_endpoint.dbx",
            "module.prod_data.databricks_cluster.etl", "module.prod_data.databricks_job.nightly",
            "azurerm_role_assignment.ci", "module.prod_data.azurerm_monitor_diagnostic_setting.dbx"})
        self.assertEqual(len(r["critical_dependents"]), 4)


if __name__ == "__main__":
    unittest.main()
