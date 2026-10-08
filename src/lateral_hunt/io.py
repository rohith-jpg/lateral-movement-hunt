"""Validated event ingestion and portable report output."""

import csv
import json
from datetime import datetime
from pathlib import Path

from .models import Alert, Event


def timestamp(value: str) -> datetime:
    """Parse an ISO timestamp and reject ambiguous naive local times."""
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return result


def load_events(path: Path) -> list[Event]:
    """Validate JSONL records and return a stable chronological timeline."""
    events = []
    seen = set()
    with Path(path).open(encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("each line must be a JSON object")
                validate_fields(event)
                for field in ("event_uid", "timestamp", "event_id", "host", "channel"):
                    if field not in event:
                        raise ValueError(f"missing {field}")
                timestamp(event["timestamp"])
                event["event_id"] = int(event["event_id"])
                if not all(
                    isinstance(event[k], str) and event[k] for k in ("event_uid", "host", "channel")
                ):
                    raise ValueError("event_uid, host and channel must be nonempty strings")
                if event["event_uid"] in seen:
                    raise ValueError("duplicate event_uid")
                seen.add(event["event_uid"])
                events.append(event)
            except (ValueError, TypeError, KeyError) as error:
                raise ValueError(f"{path}:{line_number}: {error}") from error
    return sorted(events, key=lambda e: (timestamp(e["timestamp"]), e["event_uid"]))


def write_outputs(events: list[Event], alerts: list[Alert], out: Path) -> None:
    """Write machine-readable alerts, a CSV timeline, and an analyst summary."""
    out.mkdir(parents=True, exist_ok=True)
    (out / "alerts.json").write_text(json.dumps(alerts, indent=2) + "\n", encoding="utf-8")
    fields = [
        "event_uid",
        "timestamp",
        "host",
        "channel",
        "event_id",
        "account",
        "source_host",
        "logon_type",
        "logon_id",
        "service_name",
        "image",
        "parent_image",
    ]
    with (out / "timeline.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(events)
    lines = [
        "# Hunt results",
        "",
        "Triage candidates, not a determination of malicious intent.",
        "",
        f"Events: {len(events)} | Alerts: {len(alerts)}",
        "",
    ]
    for alert in alerts:
        lines += [
            f"## {alert['rule']} ({alert['severity']})",
            "",
            f"Account: `{alert['account']}`",
            "",
            alert["reason"],
            "",
            "Evidence: " + ", ".join(alert["evidence"]),
            "",
        ]
        if "path" in alert:
            lines += ["Path: " + " → ".join(alert["path"]), ""]
    (out / "summary.md").write_text("\n".join(lines), encoding="utf-8")


def validate_fields(event: Event) -> None:
    """Reject invalid known field types before correlation can fail midway."""
    text_fields = (
        "timestamp",
        "account",
        "source_host",
        "source_ip",
        "logon_id",
        "service_name",
        "service_account",
        "image",
        "parent_image",
    )
    for field in text_fields:
        if field in event and not isinstance(event[field], str):
            raise ValueError(f"{field} must be a string when provided")
    for field in ("event_id", "logon_type"):
        if field in event:
            value = event[field]
            if isinstance(value, bool) or not isinstance(value, (int, str)):
                raise ValueError(f"{field} must be an integer or integer string")
            if isinstance(value, str) and not value.isdecimal():
                raise ValueError(f"{field} must be an integer or integer string")
