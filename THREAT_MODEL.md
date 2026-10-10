# Threat model

Protected boundary: tool execution. The agent proposes calls; only the gateway can invoke the two mock adapters. An attacker may control retrieved text and proposed arguments, but cannot edit the server registry, policy code, or approver credential in the demonstration.

Relevant attacks: instructions in lower-trust documents, capability misuse, scope escalation, restricted-data exfiltration, unknown dangerous tools, approval replay, and audit leakage. Deterministic checks enforce tool permissions and data egress regardless of injection detection. An approval binds to a SHA-256 digest of canonical arguments, expires in ten minutes, and is consumed once. Logs use redacted previews and digests instead of raw payloads.

Residual risks: heuristic detection misses paraphrased injections; local demo tokens can be guessed; the mock classifier is not a production DLP system; SQLite and JSONL are not tamper evident; a real HTTP adapter would require DNS pinning, redirect denial, allowlists, egress restrictions, and response inspection. The demo runner is a deterministic harness, not a live LLM integration.
