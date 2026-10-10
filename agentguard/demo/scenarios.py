import argparse
import json
from agentguard.core import SCENARIOS, run_scenario


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", nargs="?", default="all", choices=["all"] + list(SCENARIOS))
    args = parser.parse_args()
    for sid in SCENARIOS if args.scenario == "all" else [args.scenario]:
        print(json.dumps(run_scenario(sid), indent=2))


if __name__ == "__main__":
    main()
