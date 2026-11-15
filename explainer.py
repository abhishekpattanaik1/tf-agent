"""
LLM reasoning layer: turns deterministic findings into an explanation a reviewer
can act on in 30 seconds. Calls Azure OpenAI over plain REST (no SDK needed).

Only findings metadata is sent (addresses, types, actions, attribute PATHS),
never attribute values, so secrets and connection strings never leave TFC.

App settings:
  AZURE_OPENAI_ENDPOINT     https://<resource>.openai.azure.com
  AZURE_OPENAI_DEPLOYMENT   your deployment name (e.g. gpt-4o / gpt-4.1)
  AZURE_OPENAI_API_VERSION  default 2024-10-21
  AZURE_OPENAI_API_KEY      (Key Vault reference)  - or -
  AZURE_OPENAI_USE_MI=true  use the Function's managed identity (needs azure-identity)
"""
import json
import os
import urllib.request

SYSTEM_PROMPT = """You are a senior platform engineer reviewing a Terraform plan on Azure
(Databricks workspaces/clusters/Unity Catalog, Azure SQL/PostgreSQL, storage, networking).
You receive DETERMINISTIC findings already extracted from the plan. Do not invent resources,
attributes or values that are not in the findings. If unsure, say so.

Write concise GitHub-flavoured Markdown with these sections:
### Verdict
One line: is this plan safe to apply as-is? (The pass/fail gate is decided elsewhere; you advise.)
### What will actually happen
For each critical/high finding: the real-world impact in plain English. For example: data loss on
a DB, Databricks workspace or cluster recreated (new IDs break jobs using existing_cluster_id),
subnet recreate takes down the Databricks VNet injection, downtime, IP or ID changes.
### Likely root cause
Use action_reason/forced_by: e.g. module refactor without `moved` block, count index shift,
for_each key rename, ForceNew attribute edit, provider upgrade default change, tainted resource.
### Safe way to make this change
Concrete HCL fixes: `moved {}` blocks (use the exact addresses given), `for_each` with stable keys,
`lifecycle { prevent_destroy = true }`, `create_before_destroy`, `ignore_changes`, `terraform state mv`,
or splitting the change. Keep code blocks short.
### Reviewer checklist
3-5 checkboxes specific to this plan.
Keep the whole answer under 400 words."""


def _auth_headers():
    if os.getenv("AZURE_OPENAI_USE_MI", "").lower() == "true":
        from azure.identity import DefaultAzureCredential  # optional dependency
        tok = DefaultAzureCredential().get_token("https://cognitiveservices.azure.com/.default")
        return {"Authorization": f"Bearer {tok.token}"}
    return {"api-key": os.environ["AZURE_OPENAI_API_KEY"]}


def _slim(report):
    keep = ["severity", "action", "address", "type", "action_reason", "forced_by",
            "changed_attributes", "possible_move_to", "prod"]
    return {
        "workspace": report.get("workspace"),
        "prod_workspace": report.get("prod_workspace"),
        "summary": report["summary"],
        "findings": [{k: f.get(k) for k in keep if f.get(k)} for f in report["findings"][:40]],
        "drift": report.get("drift", [])[:20],
    }


def explain(report: dict, job: dict) -> str:
    endpoint = os.environ["AZURE_OPENAI_ENDPOINT"].rstrip("/")
    deployment = os.environ["AZURE_OPENAI_DEPLOYMENT"]
    api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-10-21")
    url = f"{endpoint}/openai/deployments/{deployment}/chat/completions?api-version={api_version}"

    user = {
        "run": {"workspace": job.get("workspace_name"), "created_by": job.get("run_created_by"),
                "message": job.get("run_message"), "speculative": job.get("is_speculative")},
        "plan_findings": _slim(report),
    }
    body = {
        "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                     {"role": "user", "content": json.dumps(user, indent=1)}],
        "temperature": 0.1,
        "max_tokens": 1200,
    }
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **_auth_headers()})
    with urllib.request.urlopen(req, timeout=90) as r:
        data = json.loads(r.read())
    return data["choices"][0]["message"]["content"].strip()
