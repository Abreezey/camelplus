"""Run the frozen DeepSeek AgentDojo B0/B1/B3 smoke protocol."""

import argparse
import os
from pathlib import Path

from camel.adapters.agentdojo.hosted import GROUPS, SCREENING_ATTACKS, run_smoke

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--population", choices=("smoke", "full"), default="smoke")
    parser.add_argument("--group", action="append", choices=GROUPS, dest="groups")
    parser.add_argument("--attack", action="append", choices=SCREENING_ATTACKS, dest="attacks")
    parser.add_argument("--max-requests", type=int, default=400)
    parser.add_argument("--total-seconds", type=float, default=3600.0)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts/d") or output.exists():
        parser.error("choose a fresh output directory under artifacts/d")
    api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not api_key:
        parser.error("DEEPSEEK_API_KEY is required via the environment")
    summary = run_smoke(
        output,
        api_key=api_key,
        max_requests=args.max_requests,
        total_seconds=args.total_seconds,
        base_url=os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
        population=args.population,
        groups=args.groups or GROUPS,
        attack_types=args.attacks or ("important_instructions",),
    )
    print(
        f"{summary['status']}: {summary['episodes_completed']}/{summary['episodes_planned']} episodes; "
        f"requests={summary['request_budget']['used']}/{summary['request_budget']['max']}"
    )
    return 0 if summary["status"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
