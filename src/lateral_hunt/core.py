"""Focused account and host correlation for lateral-movement triage."""

from .io import timestamp
from .models import Alert, Event


def same(left: str | None, right: str | None) -> bool:
    """Compare nonempty normalized identifiers without case sensitivity."""
    return bool(left and right) and str(left).casefold() == str(right).casefold()


def analyze(
    events: list[Event], service_accounts: list[str], window_minutes: int = 15
) -> list[Alert]:
    """Correlate two logons; local service/process evidence is supporting, not attribution."""
    if (
        isinstance(window_minutes, bool)
        or not isinstance(window_minutes, int)
        or window_minutes <= 0
    ):
        raise ValueError("window_minutes must be positive")
    events = sorted(events, key=lambda e: (timestamp(e["timestamp"]), e["event_uid"]))
    services = {a.casefold() for a in service_accounts}
    logons = [e for e in events if e["channel"] == "Security" and e["event_id"] == 4624]
    alerts = []
    for remote in logons:
        if (
            str(remote.get("logon_type")) != "10"
            or remote.get("account", "").casefold() not in services
        ):
            continue
        alerts.append(
            {
                "rule": "service_account_rdp",
                "severity": "medium",
                "account": remote["account"],
                "evidence": [remote["event_uid"]],
                "reason": "Configured service account used for RemoteInteractive logon; review authorization.",
            }
        )
        for first in logons:
            if str(first.get("logon_type")) != "3" or not same(
                first.get("account"), remote.get("account")
            ):
                continue
            delta = (timestamp(remote["timestamp"]) - timestamp(first["timestamp"])).total_seconds()
            if not 0 < delta <= window_minutes * 60:
                continue
            if not same(remote.get("source_host"), first["host"]):
                continue
            path = [first.get("source_host"), first["host"], remote["host"]]
            if not all(path) or len({p.casefold() for p in path}) != 3:
                continue
            middle = [
                e
                for e in events
                if same(e["host"], first["host"])
                and timestamp(first["timestamp"])
                <= timestamp(e["timestamp"])
                <= timestamp(remote["timestamp"])
            ]
            installs = [
                e
                for e in middle
                if e["channel"] == "System"
                and e["event_id"] == 7045
                and same(e.get("service_name"), "PSEXESVC")
            ]
            processes = [
                e
                for e in middle
                if (
                    (e["channel"] == "Security" and e["event_id"] == 4688)
                    or (
                        e["channel"] == "Microsoft-Windows-Sysmon/Operational"
                        and e["event_id"] == 1
                    )
                )
                and e.get("parent_image", "")
                .replace("/", "\\")
                .casefold()
                .endswith("\\psexesvc.exe")
            ]
            if not installs or not processes:
                continue
            privileges = [
                e
                for e in events
                if e["channel"] == "Security"
                and e["event_id"] == 4672
                and same(e["host"], remote["host"])
                and same(e.get("account"), remote.get("account"))
                and same(e.get("logon_id"), remote.get("logon_id"))
                and 0
                <= (timestamp(e["timestamp"]) - timestamp(remote["timestamp"])).total_seconds()
                <= 120
            ]
            evidence = [first] + installs + processes + [remote] + privileges
            alerts.append(
                {
                    "rule": "psexec_then_rdp_candidate",
                    "severity": "high",
                    "account": remote["account"],
                    "path": path,
                    "start": first["timestamp"],
                    "end": remote["timestamp"],
                    "evidence": [
                        e["event_uid"]
                        for e in sorted(evidence, key=lambda e: timestamp(e["timestamp"]))
                    ],
                    "attack": ["T1021.002", "T1021.001"],
                    "reason": "Same-account two-hop logons plus intermediate-host PsExec artifacts. "
                    "Service/process timing is circumstantial; confirm operator and session attribution.",
                }
            )
    return alerts
