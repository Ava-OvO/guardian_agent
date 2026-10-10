"""Deterministic blue-agent harness: proposals always pass through the gateway."""

from . import core


class BlueAgent:
    def __init__(self, agent_id="finance_assistant"):
        if agent_id not in core.AGENTS:
            raise ValueError("Unknown demo agent")
        self.agent_id = agent_id

    def propose(self, tool, action, arguments, source_text="", trust="trusted", source_id="blue-agent"):
        call = {"agent_id": self.agent_id, "session_id": "blue-demo", "tool": tool, "action": action, "arguments": arguments, "context": {"source_ids": [source_id]}}
        return core.submit(call, core.credentials()[self.agent_id], source_text, trust)


def legitimate_workflow():
    return BlueAgent().propose("customer_db.query", "read", {"resource": "demo_customers", "query": "aggregate_exposure"})
