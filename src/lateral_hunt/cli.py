"""Analyze normalized Windows events without contacting external services."""

import argparse
import json
from pathlib import Path

from .core import analyze
from .io import load_events, write_outputs


def main(argv: list[str] | None = None) -> None:
    """Run the offline hunt and print an actionable error for invalid input."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("data/events.jsonl"))
    parser.add_argument("--service-accounts", type=Path, default=Path("data/service_accounts.json"))
    parser.add_argument("--output", type=Path, default=Path("results"))
    parser.add_argument("--window-minutes", type=int, default=15)
    args = parser.parse_args(argv)
    try:
        events = load_events(args.input)
        accounts = json.loads(args.service_accounts.read_text(encoding="utf-8"))
        if not isinstance(accounts, list) or not all(
            isinstance(a, str) and len(a.split("\\")) == 2 and all(a.split("\\")) for a in accounts
        ):
            raise ValueError("service accounts must be a JSON list of domain-qualified names")
        alerts = analyze(events, accounts, args.window_minutes)
        write_outputs(events, alerts, args.output)
    except (OSError, ValueError) as error:
        parser.exit(2, f"Error: {error}\n")
    print(f"Analyzed {len(events)} events; {len(alerts)} alerts written to {args.output}")
