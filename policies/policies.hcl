policy "block-destructive-critical" {
  query             = "data.terraform.policies.block_destructive.deny"
  enforcement_level = "mandatory" # start with "advisory" for ~2 weeks, then switch
  description       = "Blocks destroy/replace of stateful Azure & Databricks resources unless an approver overrides"
}
