"""
Tests the outbound-only reviewer against a fake HCP Terraform API + fake Azure OpenAI.
Covers: review a run, post comment, idempotent watch (no double comments), token not
forwarded on redirect, plan values never sent to the LLM.   Run: python test_outbound.py
"""
import json, os, threading, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

PLAN = json.load(open(os.path.join(os.path.dirname(__file__), "sample_plan.json")))
S = {"comments": {"run-1": []}, "archivist_auth": "unset"}


class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _json(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path
        if p != "/archivist/plan":
            assert self.headers["Authorization"] == "Bearer team-token", p
        if p == "/api/v2/runs/run-1":
            self._json({"data": {"id": "run-1", "attributes": {"status": "policy_override", "message": "rename subnet"}},
                        "included": [{"type": "workspaces", "attributes": {"name": "dbx-platform-prod"}}]})
        elif p == "/api/v2/runs/run-1/plan/json-output":
            self.send_response(307); self.send_header("Location", f"http://127.0.0.1:{PORT}/archivist/plan"); self.end_headers()
        elif p == "/archivist/plan":
            S["archivist_auth"] = self.headers.get("Authorization"); self._json(PLAN)
        elif p == "/api/v2/runs/run-1/comments":
            self._json({"data": [{"attributes": {"body": b}} for b in S["comments"]["run-1"]]})
        elif p == "/api/v2/organizations/acme/workspaces/dbx-platform-prod":
            self._json({"data": {"id": "ws-1"}})
        elif p == "/api/v2/workspaces/ws-1/runs":
            assert "policy_override" in urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)["filter[status]"][0]
            self._json({"data": [{"id": "run-1"}]})
        else:
            self._json({"errors": [p]}, 404)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/api/v2/runs/run-1/comments":
            S["comments"]["run-1"].append(body["data"]["attributes"]["body"]); self._json({"data": {}}, 201)
        else:  # Azure OpenAI
            sent = body["messages"][1]["content"]
            assert "10.0.1.0/24" not in sent and "etl-b" not in sent, "plan VALUES leaked to LLM"
            self._json({"choices": [{"message": {"content": "### Verdict\nNot safe: subnet replace takes down VNet-injected workspace."}}]})


srv = HTTPServer(("127.0.0.1", 0), Fake); PORT = srv.server_port
threading.Thread(target=srv.serve_forever, daemon=True).start()
os.environ.update(TFC_ADDRESS=f"http://127.0.0.1:{PORT}", TFC_TOKEN="team-token",
                  AZURE_OPENAI_ENDPOINT=f"http://127.0.0.1:{PORT}", AZURE_OPENAI_DEPLOYMENT="gpt", AZURE_OPENAI_API_KEY="k")

import tfc_agent as ag  # noqa: E402

# review without posting
report, md = ag.review_run("run-1")
assert not S["comments"]["run-1"] and S["archivist_auth"] is None
assert sum(f["severity"] == "critical" for f in report["findings"]) == 3 and "AI review" in md

# watch loop once: posts once, second pass skips (idempotent via marker)
for _ in range(2):
    res = ag.review_run("run-1", post=True, skip_if_done=True)
assert len(S["comments"]["run-1"]) == 1 and ag.MARKER in S["comments"]["run-1"][0]
assert ag.workspace_id("acme", "dbx-platform-prod") == "ws-1"
print(S["comments"]["run-1"][0][:900])
print("\nALL OUTBOUND TESTS PASSED")
