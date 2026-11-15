"""
End-to-end local test: fake HCP Terraform + fake Azure OpenAI on localhost.
Covers HMAC check, test-token ping, 307 redirect (token must NOT be forwarded),
scan, LLM call, outcomes callback, and LLM-failure fallback.
Run:  python test_local.py
"""
import hashlib, hmac, json, os, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

PLAN = json.load(open(os.path.join(os.path.dirname(__file__), "sample_plan.json")))
STATE = {"callbacks": [], "archivist_auth": "unset", "llm_calls": 0, "llm_fail": False}


class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        if self.path.startswith("/api/v2/plans/"):
            assert self.headers["Authorization"] == "Bearer run-token"
            self.send_response(307); self.send_header("Location", f"http://127.0.0.1:{PORT}/archivist/plan"); self.end_headers()
        elif self.path == "/archivist/plan":
            STATE["archivist_auth"] = self.headers.get("Authorization")
            body = json.dumps(PLAN).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body)

    def do_PATCH(self):
        assert self.headers["Authorization"] == "Bearer run-token"
        assert self.headers["Content-Type"] == "application/vnd.api+json"
        STATE["callbacks"].append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response(200); self.end_headers()

    def do_POST(self):  # Azure OpenAI
        STATE["llm_calls"] += 1
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert self.headers["api-key"] == "k"
        sent = req["messages"][1]["content"]
        assert "10.0.1.0/24" not in sent and "etl-b" not in sent, "attribute VALUES leaked to LLM"
        if STATE["llm_fail"]:
            self.send_response(500); self.end_headers(); return
        out = {"choices": [{"message": {"content": "### Verdict\nNot safe to apply."}}]}
        b = json.dumps(out).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(b)


srv = HTTPServer(("127.0.0.1", 0), Fake); PORT = srv.server_port
threading.Thread(target=srv.serve_forever, daemon=True).start()
os.environ.update(AZURE_OPENAI_ENDPOINT=f"http://127.0.0.1:{PORT}", AZURE_OPENAI_DEPLOYMENT="gpt",
                  AZURE_OPENAI_API_KEY="k")

import runtask_core as rc  # noqa: E402

KEY = "s3cret"
payload = {"payload_version": 1, "stage": "post_plan", "access_token": "run-token",
           "task_result_callback_url": f"http://127.0.0.1:{PORT}/api/v2/task-results/x/callback",
           "plan_json_api_url": f"http://127.0.0.1:{PORT}/api/v2/plans/plan-1/json-output",
           "run_id": "run-1", "workspace_name": "dbx-platform-prod", "is_speculative": False,
           "run_created_by": "abhi"}
raw = json.dumps(payload).encode()
sig = hmac.new(KEY.encode(), raw, hashlib.sha512).hexdigest()

assert rc.verify_signature(raw, sig, KEY)
assert not rc.verify_signature(raw, "bad", KEY)
assert rc.parse_request(json.dumps({"access_token": "test-token"}).encode()) is None
job = rc.parse_request(raw)

# 1. normal run: prod workspace -> blocked
res = rc.process_job(job)
cb = STATE["callbacks"][-1]["data"]
assert cb["attributes"]["status"] == "failed", cb["attributes"]
assert STATE["archivist_auth"] is None, "bearer token leaked to redirect target"
outs = cb["relationships"]["outcomes"]["data"]
assert outs[0]["attributes"]["outcome-id"] == "ai-summary"
print("status :", cb["attributes"]["status"]); print("message:", cb["attributes"]["message"])
for o in outs[1:]:
    print("  ", o["attributes"]["tags"]["Severity"][0]["label"].ljust(8), o["attributes"]["description"])

# 2. LLM down -> still a decision, deterministic fallback text
STATE["llm_fail"] = True
rc.process_job(job)
cb2 = STATE["callbacks"][-1]["data"]
assert cb2["attributes"]["status"] == "failed"
assert "AI explanation unavailable" in cb2["relationships"]["outcomes"]["data"][0]["attributes"]["body"]

# 3. clean plan -> passed, no LLM call
STATE["llm_fail"] = False; calls = STATE["llm_calls"]
PLAN["resource_changes"] = [PLAN["resource_changes"][-1]]; PLAN["resource_drift"] = []
rc.process_job(job)
assert STATE["callbacks"][-1]["data"]["attributes"]["status"] == "passed" and STATE["llm_calls"] == calls
print("\nALL TESTS PASSED")
