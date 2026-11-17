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
| `tf_risk_scan.py` | Deterministic scanner. **The single source of truth** for critical resource types |
| `gen_policy.py` | Generates `policies/block_destructive.rego` from the scanner's list, so gate and reviewer agree |
| `policies/` | OPA policy set uploaded to TFC (`policies.hcl` + generated `.rego`) |
| `policy_tests/` | `opa test policies/ policy_tests/ -v` |
| `tfc_agent.py` | Outbound reviewer: `file`, `review --run`, `watch` |
| `explainer.py` | Azure OpenAI layer. Sends resource addresses and attribute *paths* only, never values |
| `terraform/policy_set.tf` | Uploads the policy set and attaches it to workspaces |
| `test_outbound.py` | End-to-end test with fake TFC + fake Azure OpenAI |
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

# 3. Policy unit tests
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
3. Restrict "override policies" permission to your approvers.

## Notes
- Workspaces need **Remote** execution mode (policies don't evaluate in Local mode).
- HCP Terraform Free: 1 policy set of up to 5 policies. This uses 1 policy.
- The OPA gate only knows the critical-type list. The richer analysis (rename detection, count-index
  shifts, AI explanation) arrives as the run comment within one poll interval.
- After editing `CRITICAL_TYPES`, run `python gen_policy.py` and re-apply the policy set.
- The Rego uses `import rego.v1`, which needs OPA ≥ 0.59 for the policy set's OPA version.
