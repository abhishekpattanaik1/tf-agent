"""
Azure Functions (Python v2 model) entry points.

  POST /api/tf-risk      <- HCP Terraform run task webhook. Verifies HMAC, enqueues, returns 200.
  queue 'tf-risk-jobs'   <- worker: scan + Azure OpenAI + callback to TFC.

Why a queue: TFC expects a fast 200 on the webhook, then a callback within 10 minutes.
The queue also gives retries if Azure OpenAI or TFC is briefly unavailable.

App settings: TFC_HMAC_KEY (Key Vault ref), AzureWebJobsStorage, AZURE_OPENAI_* (see explainer.py),
optional FAIL_ON, PROD_WORKSPACE_REGEX, PROD_ADDRESS_REGEX, REPORT_URL.
"""
import json
import logging
import os

import azure.functions as func

import runtask_core

app = func.FunctionApp()


@app.route(route="tf-risk", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
@app.queue_output(arg_name="jobs", queue_name="tf-risk-jobs", connection="AzureWebJobsStorage")
def tf_risk_webhook(req: func.HttpRequest, jobs: func.Out[str]) -> func.HttpResponse:
    raw = req.get_body()
    if not runtask_core.verify_signature(raw, req.headers.get("X-TFC-Task-Signature", ""),
                                         os.getenv("TFC_HMAC_KEY")):
        return func.HttpResponse("invalid signature", status_code=401)
    job = runtask_core.parse_request(raw)
    if job is None:  # TFC verification ping when the run task is created
        return func.HttpResponse(status_code=200)
    jobs.set(json.dumps(job))
    logging.info("queued run %s (%s)", job["run_id"], job["workspace_name"])
    return func.HttpResponse(status_code=200)


@app.queue_trigger(arg_name="msg", queue_name="tf-risk-jobs", connection="AzureWebJobsStorage")
def tf_risk_worker(msg: func.QueueMessage) -> None:
    job = json.loads(msg.get_body())
    result = runtask_core.process_job(job)
    logging.info("run %s -> %s", job["run_id"], result["data"]["attributes"]["status"])
