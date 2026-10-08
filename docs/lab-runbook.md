# Optional real Windows lab

This runbook is provided for a future authorized lab execution. The checked-in dataset was generated offline, not collected from these machines.

## Topology

Use an isolated virtual switch with DC-01 (AD DS/DNS), PC-01, PC-02 and FILE-01, plus a SIEM collector if separate. The screenshot's named path needs three member endpoints in addition to the domain controller. Use a private lab domain such as `lab.test`; never connect it to a production domain. Snapshot guests and record their UTC clock offsets.

Suggested example addresses: DC-01 10.10.10.10, PC-01 .11, PC-02 .12 and FILE-01 .13. Size VMs according to the chosen OS requirements and available hardware. Windows installation media, licenses and a virtualization platform are prerequisites, not bundled deliverables.

## Telemetry prerequisites

1. Join member hosts to the lab domain. Create disposable test identities, including svc-backup. Record its expected normal batch/network activity and temporary lab privileges.
2. Enable advanced audit policy for Logon (success/failure), Special Logon (success), Process Creation (success), and applicable explicit-credential auditing. Enable command-line inclusion for process creation if desired; command lines can contain secrets.
3. Install Sysmon from Microsoft's official distribution after reviewing its license. Capture ProcessCreate events; record the version and actual configuration.
4. Collect **Security, System, and Microsoft-Windows-Sysmon/Operational** channels. System is necessary for 7045 and is easy to overlook when collecting only Security/Sysmon.
5. In a chosen SIEM, verify event arrival, event time parsing, hostname, source address, target/subject account distinction, and logon IDs. Confirm a harmless local process and test logon before emulation.

## Controlled activity

In the isolated lab only, use Microsoft's PsExec from PC-01 against PC-02 under the disposable test identity to execute a harmless identity command (`whoami`). Use the tool's supported credential prompt; do not put passwords in scripts or saved command lines. Then open Remote Desktop on PC-02 and connect to FILE-01 using the test account. Close sessions when complete. The precise service and process behavior can vary with version and execution options; record what actually happens rather than expecting the synthetic timings verbatim.

Do not weaken host protections or open remote-access ports outside the isolated network. This project does not automatically install tools, configure the domain, grant privileges or run remote commands.

## Capture and acceptance criteria

- Export relevant events from all three channels on every participating host for the exercise window, retaining raw EVTX privately.
- Compute SHA-256 hashes (`Get-FileHash -Algorithm SHA256`) and record export time, host, clock offset, OS/tool versions and operator actions.
- Normalize records using [the data contract](data-contract.md); resolve source addresses from lab inventory at event time.
- Run `python hunt.py --input private-data/normalized.jsonl --output results/real-lab` with the appropriate service-account inventory.
- Confirm the observed path manually from source/destination evidence. If no chain fires, report missing conditions; do not invent events to fit the rule.
- Repeat with approved helpdesk RDP, regular backup activity, and separated time windows. Document false positives and false negatives.
- Reset test credentials and restore lab snapshots when finished. Keep originals and redact any exported portfolio evidence.

## Splunk use

The queries in `detections/hunts.spl` target the included normalized JSON schema. Ingest the synthetic JSONL as one JSON object per event into a dedicated `lateral_lab` index, using a JSON sourcetype with event-time extraction for `timestamp`. Ensure `spath` exposes the documented fields. Do not run these unchanged against arbitrary `WinEventLog` field names.

Validate the account timeline and service-account RDP search first. Use the offline analyzer for the full host/time chain; the SQL-like idea of joining by account alone is insufficient. The SIEM templates are not claimed to implement the full Python correlation or to have been tested on a live Splunk instance.
