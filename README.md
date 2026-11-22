# tf-risk-agent: Terraform change-risk gate for HCP Terraform (Azure), outbound-only

Blocks applies that would **destroy or recreate** stateful Azure / Databricks resources
and explains each risky change, with the safe fix, using Azure OpenAI.
**Nothing needs to reach into your network.** Only outbound HTTPS is used.

```
 terraform apply (CLI) / Start run (UI)
          │
          ▼
 ┌──── HCP Terraform ─────────────────────────┐
 │ plan → OPA policy set (runs INSIDE TFC)    │   ① GATE: deterministic, no endpoint
 │        critical destroy/replace? → BLOCK   │      approver can Override (audited)
 │                                            │
 │ run page ◄── comment: report + AI review ──┼──┐ ② EXPLAIN: outbound-only poller
 └────────────────────────────────────────────┘  │
                         ▲ GET runs / plan JSON   │
                         │ POST comment           │
               tfc_agent.py (laptop / VM / Function timer / ADO agent in your VNet)
                         │
                         └──► Azure OpenAI (private endpoint OK)
```

## Files
| File | Purpose |
|---|---|
| `tf_risk_scan.py` | Deterministic scanner. **The single source of truth** for critical resource types. Also pairs deleted/created resources into `moved {}` suggestions |
| `blast_radius.py` | Dependency graph from the plan JSON (`configuration` + `prior_state`): for each destroy/replace, lists what depends on it |
| `gen_policy.py` | Generates `policies/block_destructive.rego` from the scanner's list, so gate and reviewer agree |
| `policies/` | OPA policy set uploaded to TFC (`policies.hcl` + generated `.rego`) |
| `policy_tests/` | `opa test policies/ policy_tests/ -v` |
| `tfc_agent.py` | Outbound reviewer: `file`, `review --run`, `watch` |
| `explainer.py` | Azure OpenAI layer. Sends resource addresses and attribute *paths* only, never values |
| `terraform/policy_set.tf` | Uploads the policy set and attaches it to workspaces |
| `test_outbound.py`, `test_local.py` | End-to-end tests with fake TFC + fake Azure OpenAI |
| `tests/` | Unit tests for the scanner, blast radius and poller: `python -m unittest discover -s tests -t .` |
| `function_app.py`, `runtask_core.py`, `terraform/run_task.tf` | *Optional*: push-based run task, only if you later get an inbound endpoint or TFC request forwarding |

## Test in 3 steps (laptop, outbound only)
```bash
# 1. Offline: a plan you already have (no TFC, no network)
terraform show -json tfplan > plan.json          # or download from a past run
python tfc_agent.py file plan.json --workspace dbx-prod

# 2. A real past run: read-only, posts nothing
export TFC_TOKEN=...   # team token with ADMIN on that workspace (required by TFC for plan JSON)
export AZURE_OPENAI_ENDPOINT=https://<res>.openai.azure.com AZURE_OPENAI_DEPLOYMENT=<dep> AZURE_OPENAI_API_KEY=...
python tfc_agent.py review --run run-XXXX

# 3. Unit tests (no network) + policy tests
python -m unittest discover -s tests -t .
opa test policies/ policy_tests/ -v
```
**Back-test first:** run step 2 on the runs behind your past recreate incidents. Every one must show 🔴 critical.

## Go live
1. `cd terraform && terraform apply -target=tfe_policy_set.tf_risk` with 2-3 workspaces.
   Keep `enforcement_level = "advisory"` in `policies/policies.hcl` for ~2 weeks, then switch to `"mandatory"`.
2. Run the poller somewhere with outbound 443 to `app.terraform.io`, `archivist.terraform.io` and Azure OpenAI:
   `python tfc_agent.py watch --org <org> --workspaces ws1,ws2 --interval 60`
   Options: a small VM or container, a Function **timer trigger**, or a scheduled job on a self-hosted ADO agent.
   It's idempotent (one comment per run, tracked via a hidden marker), so restarts are safe.
   Handled run IDs are kept in `--state-file` (default `./.tf-risk-agent-state.json`, or `TF_RISK_STATE`)
   so each poll only calls the API for new runs. Put it on persistent storage; if it's lost, the marker
   still prevents duplicate comments. Runs that auto-apply before the poller sees them are still
   reviewed, and the comment is labeled as a post-apply audit record.
3. Restrict "override policies" permission to your approvers.

## Notes
- Workspaces need **Remote** execution mode (policies don't evaluate in Local mode).
- HCP Terraform Free: 1 policy set of up to 5 policies. This uses 1 policy.
- The OPA gate only knows the critical-type list. The richer analysis (rename detection, count-index
  shifts, AI explanation) arrives as the run comment within one poll interval.
- After editing `CRITICAL_TYPES`, run `python gen_policy.py` and re-apply the policy set.
- The Rego uses `import rego.v1`, which needs OPA ≥ 0.59 for the policy set's OPA version.
- `CRITICAL_TYPES` uses exact type names on purpose. Broad globs (`azurerm_mssql_*`) also match firewall
  rules and auditing policies, and false blocks teach people to click Override. `tests/` fails if the
  `.rego` is out of date with the list.
- Prod detection matches `prod` / `production` as a whole word: `dbx-prod` and `module.prod_data`
  count as prod, `nonprod`, `preprod` and `pre-prod` don't. Override with `PROD_WORKSPACE_REGEX` / `PROD_ADDRESS_REGEX`.
- **Blast radius** comes from references, `depends_on`, module inputs/outputs, module-level count/for_each,
  **provider configs** (a `databricks` provider whose `host` points at an Azure workspace makes every
  `databricks_*` resource depend on it) and state `depends_on` (which also covers references through
  `local.*`, which the plan JSON omits). Dependents outside Terraform are not visible. It informs the
  report and the AI review; it does **not** change the gate decision.
- The AI review gets the gate decision and must not contradict it. Run message and author are passed
  as `untrusted` data so the model treats them as text, not instructions.
