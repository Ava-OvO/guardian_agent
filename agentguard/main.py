"""Single entry point for dashboard, scenario replay, and evaluation."""

import argparse
import json


def main():
    parser = argparse.ArgumentParser(description="AgentGuard demo")
    parser.add_argument("command", nargs="?", choices=["dashboard", "evaluate", "replay"], default="dashboard")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--llm", action="store_true", help="Include configured live LLM benchmark")
    parser.add_argument("--case", default="S2", help="Case ID for replay")
    args = parser.parse_args()
    if args.command == "dashboard":
        from .server import Handler
        from . import core
        from http.server import ThreadingHTTPServer
        core.init_db()
        server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
        print("AgentGuard dashboard: http://127.0.0.1:%s" % args.port, flush=True)
        server.serve_forever()
    elif args.command == "evaluate":
        from .evaluation import run
        print(json.dumps(run(include_llm=args.llm), ensure_ascii=False, indent=2))
    else:
        from .red_agent import replay
        print(json.dumps(replay(args.case), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
