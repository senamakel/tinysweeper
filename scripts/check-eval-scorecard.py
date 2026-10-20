#!/usr/bin/env python3
"""Validate and summarize one exact offline replay group scorecard."""

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scorecard", type=Path)
    parser.add_argument("--expected", action="append", required=True)
    args = parser.parse_args()

    try:
        card = json.loads(args.scorecard.read_text())
    except (OSError, json.JSONDecodeError) as error:
        parser.error(f"cannot read scorecard: {error}")

    cases = card.get("cases")
    if not isinstance(cases, list):
        parser.error("scorecard has no case list")
    expected = set(args.expected)
    observed = [case.get("id") for case in cases]
    if len(observed) != len(expected) or set(observed) != expected:
        parser.error(
            "selected case set differs: expected "
            f"{sorted(expected)}, received {sorted(observed)}"
        )
    if card.get("loose_replays") != 0:
        parser.error(f"strict replay required; loose_replays={card.get('loose_replays')!r}")

    errors = [case["id"] for case in cases if case.get("error")]
    if errors:
        parser.error(f"strict replay/review errors: {', '.join(sorted(errors))}")

    limits = card.get("execution_limits")
    if not isinstance(limits, dict) or set(limits.get("selected_case_ids", [])) != expected:
        parser.error("scorecard does not persist the exact selected-case execution limits")

    matched = sum(case.get("true_positives", 0) for case in cases)
    missed = sum(len(case.get("missed", [])) for case in cases)
    print(f"## Offline replay: {args.scorecard.parent.name}\n")
    print(f"- Cases: {len(cases)} ({', '.join(sorted(observed))})")
    print("- Strict errors: 0; loose replays: 0")
    print(f"- Expected labels matched/missed: {matched}/{missed}")
    print(f"- Execution limits: `{json.dumps(limits, sort_keys=True)}`")
    return 0


if __name__ == "__main__":
    sys.exit(main())
