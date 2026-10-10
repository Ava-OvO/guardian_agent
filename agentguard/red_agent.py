"""Controlled red-agent harness using only synthetic local test cases."""

import json
from pathlib import Path

from . import core

ATTACKS_PATH = Path(__file__).parent / "data" / "attacks.json"


def cases():
    return json.loads(ATTACKS_PATH.read_text(encoding="utf8"))


def replay(case_id):
    case = next(item for item in cases() if item["id"] == case_id)
    call = json.loads(core.canonical(case["call"]))
    result = core.submit(call, core.credentials()[call["agent_id"]], case["source"], case["trust"], case["title"])
    return {"case_id": case_id, "expected": case["expected"], "result": result}
