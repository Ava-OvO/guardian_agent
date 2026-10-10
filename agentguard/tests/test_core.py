import json
import os
import tempfile
import unittest
from pathlib import Path

from agentguard import core


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        core.DB_PATH = Path(self.tmp.name) / "events.sqlite3"
        core.AUDIT_PATH = Path(self.tmp.name) / "audit.jsonl"
        core.init_db()

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, sid):
        return json.loads(core.canonical(core.SCENARIOS[sid]["call"]))

    def test_scenarios(self):
        expected = {"S1": "allow", "S2": "deny", "S3": "deny", "S4": "require_approval", "S5": "deny"}
        for sid, decision in expected.items():
            self.assertEqual(core.run_scenario(sid)["gateway"]["decision"], decision)
        self.assertEqual(len(core.events()), 5)

    def test_identity_and_unknown_tool(self):
        call = self.call("S1")
        self.assertEqual(core.submit(call, "wrong")["decision"], "deny")
        call["tool"] = "shell.exec"
        self.assertEqual(core.submit(call, core.credentials()["finance_assistant"])["decision"], "deny")

    def test_claimed_labels_do_not_override_classification(self):
        call = self.call("S2")
        call["context"]["data_labels"] = ["public"]
        decision = core.submit(call, core.credentials()["finance_assistant"])
        self.assertIn("RESTRICTED_DATA_EXTERNAL_DESTINATION", decision["reason_codes"])

    def test_approval_exact_hash_one_time_and_reject(self):
        call = self.call("S4")
        response = core.submit(call, core.credentials()["finance_assistant"])
        self.assertFalse(response["executed"])
        approval = core.approvals()[0]
        with self.assertRaises(ValueError):
            core.decide_approval(approval["id"], core.credentials()["approver"], True, core.digest({"changed": True}))
        with self.assertRaises(PermissionError):
            core.decide_approval(approval["id"], "wrong", True, approval["args_digest"])
        resolved = core.decide_approval(approval["id"], core.credentials()["approver"], True, approval["args_digest"])
        self.assertEqual(resolved["result"]["network_request"], False)
        with self.assertRaises(ValueError):
            core.decide_approval(approval["id"], core.credentials()["approver"], True, approval["args_digest"])

    def test_audit_redacts_canary(self):
        core.run_scenario("S2")
        audit = core.AUDIT_PATH.read_text()
        self.assertNotIn("FLAG{synthetic-canary}", audit)
        self.assertIn("[REDACTED]", audit)


if __name__ == "__main__":
    unittest.main()
