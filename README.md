# tf-risk-agent: Terraform change-risk gate for HCP Terraform (Azure)

Blocks applies that would **destroy or recreate** stateful Azure / Databricks resources
(SQL/Postgres, storage, Key Vault, VNets/subnets, Databricks workspaces, clusters, UC objects).
Explains each risky change and the safe fix using Azure OpenAI.
Works with manual applies from the **CLI or the TFC UI**; no CI pipeline needed.

```
terraform plan/apply (CLI or UI) ─► TFC run ─► post_plan run task ─► Azure Function (HTTP)
                                                                     │ verify HMAC, enqueue, 200
                                                                     ▼
                                              Azure Function (queue worker)
                                              1. download plan JSON (run-scoped token)
                                              2. tf_risk_scan → findings + PASS/FAIL  (deterministic)
                                              3. Azure OpenAI → explanation + fix     (advisory only)
                                              4. PATCH result + outcomes to TFC
                                                                     ▼
                                   FAILED + mandatory ⇒ "Confirm & Apply" blocked; override is audited
```

## Files
| File | Purpose |
|---|---|
| `tf_risk_scan.py` | Deterministic scanner (also a standalone CLI: `python tf_risk_scan.py plan.json`) |
| `runtask_core.py` | Run-task protocol: HMAC, plan download, callback with outcomes |
| `explainer.py` | Azure OpenAI reasoning layer (REST, no SDK). Sends attribute *paths* only, never values |
| `function_app.py` | Azure Functions entry points (HTTP webhook + queue worker) |
| `terraform/run_task.tf` | Registers the run task and attaches it to workspaces (tfe provider) |
| `test_local.py` | End-to-end test with fake TFC + fake Azure OpenAI |

## Prerequisites to check
- Workspaces must use **Remote** (or Agent) execution mode. Run tasks don't fire in *Local* mode.
- HCP Terraform Free allows 1 run task on up to 10 workspaces; paid tiers lift this.
- The Function must be reachable from HCP Terraform (public HTTPS + function key + HMAC).
  For a private-only endpoint you need TFC agents with request forwarding (Premium).

## Deploy
1. Function App (Python 3.11, Linux, Consumption or Flex) with a managed identity.
2. App settings:
   - `TFC_HMAC_KEY`: random 32+ chars, as a Key Vault reference
   - `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_DEPLOYMENT`, and either `AZURE_OPENAI_API_KEY`
     (Key Vault ref) or `AZURE_OPENAI_USE_MI=true` plus the *Cognitive Services OpenAI User* role
   - Optional: `PROD_WORKSPACE_REGEX` (default `prod`), `FAIL_ON` (default `critical`)
3. `func azure functionapp publish <app-name>`
4. `cd terraform && terraform apply`. Set `agent_url` to `https://<app>.azurewebsites.net/api/tf-risk?code=<function key>`.

## Rollout (recommended)
1. **Back-test:** for each past incident, export that run's plan JSON from TFC and run
   `python tf_risk_scan.py plan.json`. Every incident must come out **critical**.
2. **Advisory for about 2 weeks** on 2-3 workspaces. Tune `CRITICAL_TYPES` to cut false positives.
3. **Mandatory** (`enforcement_level = "mandatory"`). Restrict who can override failed tasks
   to your approvers. Overrides are recorded in the run history, which gives you the audit trail.

## Tuning
- `CRITICAL_TYPES` / `SENSITIVE_UPDATE_TYPES` in `tf_risk_scan.py`: add your own module resource types.
- The LLM never decides pass/fail. If Azure OpenAI is down, the gate still works and shows the deterministic report.
- If the agent itself errors, the task reports **failed** (fail-closed) with the reason, and an approver can override.
