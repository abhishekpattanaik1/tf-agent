# Uploads ../policies as an OPA policy set and attaches it to the chosen workspaces.
# Runs entirely inside HCP Terraform: no inbound connectivity to your network needed.

terraform {
  required_providers {
    tfe = { source = "hashicorp/tfe", version = "~> 0.60" }
  }
}

variable "organization" { type = string }
variable "workspace_names" { type = list(string) } # start with 2-3, then roll out

data "tfe_workspace" "targets" {
  for_each     = toset(var.workspace_names)
  name         = each.key
  organization = var.organization
}

data "tfe_slug" "policies" {
  source_path = "${path.module}/../policies"
}

resource "tfe_policy_set" "tf_risk" {
  name          = "tf-risk-block-destructive"
  description   = "Blocks destroy/replace of stateful Azure & Databricks resources (generated from tf_risk_scan.py)"
  organization  = var.organization
  kind          = "opa"
  overridable   = true # approvers with override permission can push intentional destroys through (audited)
  workspace_ids = [for w in data.tfe_workspace.targets : w.id]
  slug          = data.tfe_slug.policies
  # policy_tool_version = "<latest OPA version offered in your org>"  # Rego uses `import rego.v1`: needs OPA >= 0.59
}
