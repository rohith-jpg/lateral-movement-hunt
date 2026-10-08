"""Generate illustrative, synthetic normalized events; never collects host logs."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
events = []


def add(
    uid: str, time: str, host: str, event_id: int, channel: str = "Security", **fields: object
) -> None:
    """Append a synthetic event to the demonstration fixture."""
    events.append(
        dict(
            event_uid=uid,
            timestamp=f"2026-10-08T{time}Z",
            host=host,
            event_id=event_id,
            channel=channel,
            synthetic=True,
            **fields,
        )
    )


def main() -> None:
    """Rebuild the checked-in fixture without collecting host data."""
    events.clear()
    add(
        "E01",
        "10:01:00",
        "PC-01",
        4648,
        account="LAB\\svc-backup",
        target_host="PC-02",
        image="C:\\Tools\\PsExec.exe",
    )
    add(
        "E02",
        "10:02:00",
        "PC-02",
        4624,
        account="LAB\\svc-backup",
        source_host="PC-01",
        source_ip="10.10.10.11",
        logon_type=3,
        logon_id="0x101",
    )
    add(
        "E03",
        "10:03:00",
        "PC-02",
        7045,
        channel="System",
        service_name="PSEXESVC",
        image="C:\\Windows\\PSEXESVC.exe",
        service_account="LocalSystem",
    )
    add(
        "E04",
        "10:05:00",
        "PC-02",
        4688,
        account="NT AUTHORITY\\SYSTEM",
        logon_id="0x3e7",
        image="C:\\Windows\\System32\\cmd.exe",
        parent_image="C:\\Windows\\PSEXESVC.exe",
        command_line="cmd.exe /c whoami",
    )
    add(
        "E05",
        "10:05:00",
        "PC-02",
        1,
        channel="Microsoft-Windows-Sysmon/Operational",
        account="NT AUTHORITY\\SYSTEM",
        image="C:\\Windows\\System32\\cmd.exe",
        parent_image="C:\\Windows\\PSEXESVC.exe",
        process_guid="{00000000-0000-0000-0000-000000000005}",
    )
    add(
        "E06",
        "10:11:00",
        "FILE-01",
        4624,
        account="LAB\\svc-backup",
        source_host="PC-02",
        source_ip="10.10.10.12",
        logon_type=10,
        logon_id="0x201",
    )
    add(
        "E07",
        "10:11:01",
        "FILE-01",
        4672,
        account="LAB\\svc-backup",
        logon_id="0x201",
        privileges="SeDebugPrivilege",
    )
    # Negative controls: normal user RDP, service network/batch use, unsuccessful logon.
    add(
        "B01",
        "09:00:00",
        "FILE-01",
        4624,
        account="LAB\\svc-backup",
        source_host="BACKUP-01",
        logon_type=3,
        logon_id="0x301",
    )
    add(
        "B02",
        "09:00:01",
        "FILE-01",
        4624,
        account="LAB\\svc-backup",
        logon_type=4,
        logon_id="0x302",
    )
    add(
        "B03",
        "09:10:00",
        "PC-02",
        4624,
        account="LAB\\helpdesk",
        source_host="ADMIN-01",
        logon_type=10,
        logon_id="0x401",
    )
    add("B04", "09:11:00", "PC-02", 4672, account="LAB\\helpdesk", logon_id="0x401")
    add("B05", "09:20:00", "FILE-01", 4625, account="LAB\\user1", source_host="PC-01", logon_type=3)
    add(
        "B06",
        "09:30:00",
        "PC-02",
        7045,
        channel="System",
        service_name="ApprovedAgent",
        image="C:\\Program Files\\Example\\agent.exe",
    )
    add("B07", "10:11:01", "OTHER-01", 4672, account="LAB\\svc-backup", logon_id="0x201")
    events.sort(key=lambda e: (e["timestamp"], e["event_uid"]))
    destination = ROOT / "data" / "events.jsonl"
    destination.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    print(f"Wrote {len(events)} synthetic events to {destination}")


if __name__ == "__main__":
    main()
