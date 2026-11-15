# Registers the tf-risk-agent as a MANDATORY post-plan run task on the chosen workspaces.
# A failed mandatory task blocks "Confirm & Apply" in the UI and `terraform apply` from the CLI.
# Intentional destroys go through TFC's audited "Override" (grant only to approvers).

terraform {
  required_providers {
    tfe = { source = "hashicorp/tfe", version = "~> 0.60" }
  }
}

variable "organization"      { type = string }
variable "agent_url"         { type = string }                    # https://<func>.azurewebsites.net/api/tf-risk?code=<function-key>
variable "hmac_key" {                                             # same value as TFC_HMAC_KEY app setting
  type      = string
  sensitive = true
}
variable "workspace_names"   { type = list(string) }              # start with 2-3 workspaces, then roll out
variable "enforcement_level" {
  type    = string
  default = "advisory"                                            # run advisory for ~2 weeks, then "mandatory"
}

resource "tfe_organization_run_task" "tf_risk" {
  organization = var.organization
  name         = "tf-risk-agent"
  url          = var.agent_url
  hmac_key     = var.hmac_key
  enabled      = true
  description  = "Blocks destroy/replace of stateful Azure & Databricks resources; AI explanation via Azure OpenAI"
}

data "tfe_workspace" "targets" {
  for_each     = toset(var.workspace_names)
  name         = each.key
  organization = var.organization
}

resource "tfe_workspace_run_task" "tf_risk" {
  for_each          = data.tfe_workspace.targets
  workspace_id      = each.value.id
  task_id           = tfe_organization_run_task.tf_risk.id
  enforcement_level = var.enforcement_level
  stages            = ["post_plan"]
}
