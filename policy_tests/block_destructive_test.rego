# Run locally:  opa test policies/ policy_tests/ -v
package terraform.policies.block_destructive_test

import rego.v1

import data.terraform.policies.block_destructive as p

rc(t, actions) := {"address": sprintf("%s.x", [t]), "mode": "managed", "type": t, "change": {"actions": actions}}

test_blocks_sql_db_delete if {
	count(p.deny) == 1 with input as {"plan": {"resource_changes": [rc("azurerm_mssql_database", ["delete"])]}}
}

test_blocks_subnet_replace if {
	some m in p.deny with input as {"plan": {"resource_changes": [rc("azurerm_subnet", ["delete", "create"])]}}
	startswith(m, "REPLACE")
}

test_blocks_databricks_workspace_replace if {
	count(p.deny) == 1 with input as {"plan": {"resource_changes": [rc("azurerm_databricks_workspace", ["create", "delete"])]}}
}

test_allows_in_place_update if {
	count(p.deny) == 0 with input as {"plan": {"resource_changes": [rc("azurerm_mssql_database", ["update"])]}}
}

test_allows_noncritical_replace if {
	count(p.deny) == 0 with input as {"plan": {"resource_changes": [rc("azurerm_log_analytics_workspace", ["delete", "create"])]}}
}

test_ignores_data_sources if {
	count(p.deny) == 0 with input as {"plan": {"resource_changes": [object.union(rc("azurerm_subnet", ["delete"]), {"mode": "data"})]}}
}
