# AgentGuard

Python-only agent runtime security gateway and SOC dashboard for the Secure Horizons hackathon. The default demo uses synthetic data and a mock outbound adapter: it never sends HTTP requests to the destinations in attack scenarios. Python 3.9+ and the standard library are sufficient.

## Run locally

```bash
cd /Users/iron9/Documents/Coding/guardian_agent
python3 -m agentguard.server
```

Open **http://127.0.0.1:8000**. The dashboard is in English and presents the decision before the technical details. Go to **Interactive Demo**, run S1–S5, then inspect **Tool Call Log**, **Security Overview**, and **Approvals**. For S4, click **Approve mock execution** or **Reject**. The default local approver token is `demo-approver-token`; change all demo tokens via environment variables before sharing the machine or binding to a non-loopback address. The dashboard polls every three seconds.

CLI replay:

```bash
python3 -m agentguard.demo.scenarios all
python3 -m unittest discover -s agentguard/tests -v
python3 -m agentguard.main evaluate
```

Health and API examples:

```bash
curl http://127.0.0.1:8000/health
curl -H 'Authorization: Bearer demo-console-token' http://127.0.0.1:8000/api/v1/events
curl -X POST -H 'Authorization: Bearer demo-console-token' http://127.0.0.1:8000/api/v1/demo/run/S2
curl -X POST -H 'Authorization: Bearer demo-finance-token' -H 'Content-Type: application/json' \
  -d '{"agent_id":"finance_assistant","session_id":"api-example","tool":"customer_db.query","action":"read","arguments":{"resource":"demo_customers","query":"aggregate_exposure"}}' \
  http://127.0.0.1:8000/api/v1/tool-calls
```

`GET /api/v1/approvals` returns the `args_digest` for each pending request. Send it in `{"args_digest":"..."}` to `POST /api/v1/approvals/{id}/approve` or `/reject` with `Authorization: Bearer <approver-token>`. Approval expires after ten minutes and is one-use.

## Policy versus LLM Guardian

The project now includes `blue_agent.py`, `red_agent.py`, `guardian.py`, `tools.py`, `evaluation.py`, `dashboard.py`, synthetic `data/attacks.json`, and `results/test_results.json` under `agentguard/`. The built-in dashboard has a **方案评估** page. `agentguard/dashboard.py` is an optional Streamlit view.

Run `python3 -m agentguard.main evaluate` for the deterministic baseline. On the eight synthetic cases currently included, policy alone matches six exact decisions (75%), with one malicious case allowed and another queued for approval instead of denied. This small benchmark is illustrative, not a production security rate.

To test an actual model, provide a credential-free HTTPS OpenAI-compatible chat-completions URL plus model name and API key through `AGENTGUARD_LLM_URL`, `AGENTGUARD_LLM_MODEL`, and `AGENTGUARD_LLM_API_KEY`, then run `python3 -m agentguard.main evaluate --llm`. The key is never written to results. If the Kiro API differs, its request/response contract is needed for an adapter. LLM reviews redacted synthetic content only. Hard policy denial always wins; the model can add an injection-based denial but cannot grant permission. Without configured model credentials, no LLM performance claim is made. More detail is in [agentguard/README.md](agentguard/README.md).

## Architecture

`agentguard/core.py` handles identity, capability checks, argument validation, classification, policy, mock tool execution, approval state, and audit writes. `agentguard/server.py` exposes the API and serves the dashboard in `agentguard/static`. SQLite lives in `runtime/agentguard.sqlite3`; a redacted JSONL audit stream lives in `runtime/audit.jsonl`. Both are gitignored. `agentguard/demo/scenarios.py` runs the same five scenarios as the UI.

Policy precedence is fixed: invalid identity, malformed/unknown tools, missing capability or scope, and restricted external transfer deny; outbound requests without a hard deny require human approval; safe finance aggregate lookup is allowed; all other calls deny. The `context.data_labels` client field cannot lower trusted classification. Source text can add an injection signal but never grants authorization. Every allowed execution goes through the mock adapter.

## Two-minute jury demo

1. Show the empty overview and explain that AgentGuard is at the **tool boundary**.
2. Run S1: synthetic aggregate lookup succeeds.
3. Run S2: an untrusted document asks to send a canary to an external URL; the call is blocked for restricted-data exfiltration, with an injection signal.
4. Run S3 and S5: scope violation and unknown shell tool are blocked.
5. Run S4: the outbound call is queued. Inspect its exact hash, approve it, and point out `network_request: false` in the mock outcome.
6. Open Live Events and inspect policy reasons, source provenance, redacted arguments, and the JSONL audit file.

## AWS / Kiro connection

The AWS participant guide says the team sandbox is in `us-east-1`, lasts only during the event, and may contain only synthetic, anonymized, or public data. This local demo does not need AWS credentials or a Kiro API key. Keep the dashboard local for now. For a later AWS integration, put the gateway before your team-owned AgentCore Gateway/Lambda tools, use one IAM role per agent/tool, and forward only redacted events to CloudWatch. Keep demo attack targets in your own team account. Do not paste temporary Workshop Studio credentials or Kiro keys into code or chat; pass them through environment variables or AWS Secrets Manager when connecting an adapter. No real outbound adapter is included yet.

## Limits

This is a hackathon prototype. The heuristic injection scanner is incomplete; body classification recognizes only controlled demo data; the JSONL file is append-only by application convention, not tamper-proof; the local token scheme is not SSO; the UI carries a default demo token; there is no DNS resolution or redirect handling because there are no real outbound requests. Do not expose this server publicly or use it to protect real data without hardening identity, storage, policy management, and network controls.
