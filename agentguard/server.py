import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import core

STATIC = Path(__file__).parent / "static"


class Handler(BaseHTTPRequestHandler):
    def send_json(self, value, status=200):
        data = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def token(self):
        value = self.headers.get("Authorization", "")
        return value[7:] if value.startswith("Bearer ") else ""

    def body(self):
        size = int(self.headers.get("Content-Length", "0"))
        if size > 12000:
            raise ValueError("Request too large")
        return json.loads(self.rfile.read(size) or b"{}")

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html", "/app.js", "/style.css"):
            name = "index.html" if path == "/" else path[1:]
            data = (STATIC / name).read_bytes()
            mime = "text/html" if name.endswith("html") else "text/javascript" if name.endswith("js") else "text/css"
            self.send_response(200)
            self.send_header("Content-Type", mime + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/health":
            return self.send_json({"status": "ok", "mode": "local_demo", "policy_version": core.POLICY_VERSION})
        if not core.authenticate(self.token(), "demo") and not core.authenticate(self.token(), "approver"):
            return self.send_json({"error": "Dashboard credential required"}, 401)
        if path == "/api/v1/events":
            q = parse_qs(urlparse(self.path).query)
            return self.send_json(core.events({k: q[k][0] for k in ("decision", "severity", "agent_id") if k in q}))
        if path == "/api/v1/metrics":
            events = core.events()
            return self.send_json({"total": len(events), "allowed": sum(e["decision"] in ("allow", "approved") for e in events), "blocked": sum(e["decision"] in ("deny", "rejected") for e in events), "pending": sum(a["status"] == "pending" for a in core.approvals()), "attacks": {a: sum(e["attack"] == a for e in events) for a in sorted({e["attack"] for e in events if e["attack"]})}})
        if path == "/api/v1/agents":
            return self.send_json([dict(agent_id=k, **v) for k, v in core.AGENTS.items()])
        if path == "/api/v1/approvals":
            return self.send_json(core.approvals())
        if path == "/api/v1/scenarios":
            return self.send_json([{**{k: v for k, v in s.items() if k != "call"}, "id": sid} for sid, s in core.SCENARIOS.items()])
        if path == "/api/v1/policies":
            return self.send_json({"version": core.POLICY_VERSION, "rules": ["Unknown tool and invalid identity: deny", "Capability and resource scope violation: deny", "Restricted data to external destination: deny", "External POST: require exact-call human approval", "Finance aggregate read: allow", "Everything else: deny"]})
        self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            body = self.body()
            if path == "/api/v1/tool-calls":
                return self.send_json(core.submit(body, self.token()))
            if path.startswith("/api/v1/demo/run/"):
                if not core.authenticate(self.token(), "demo"):
                    return self.send_json({"error": "Demo credential required"}, 401)
                sid = path.rsplit("/", 1)[-1].upper()
                return self.send_json(core.run_scenario(sid))
            if path.startswith("/api/v1/approvals/"):
                parts = path.split("/")
                if len(parts) == 6 and parts[-1] in ("approve", "reject"):
                    return self.send_json(core.decide_approval(parts[-2], self.token(), parts[-1] == "approve", body.get("args_digest")))
            return self.send_json({"error": "Not found"}, 404)
        except PermissionError as exc:
            self.send_json({"error": str(exc)}, 403)
        except KeyError as exc:
            self.send_json({"error": str(exc)}, 404)
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, 400)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    core.init_db()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print("AgentGuard dashboard: http://%s:%s" % (args.host, args.port), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
