# Normalized data contract

Input is UTF-8 JSON Lines: one object per event. It is **not** raw Windows Event XML, EVTX, a Splunk export, or native Wazuh JSON. Convert records to this contract before running the offline tool. No adapter for arbitrary raw formats is claimed.

| Field | Meaning |
|---|---|
| event_uid | Unique collection record identity; duplicates rejected |
| timestamp | ISO-8601 event time with timezone, preferably UTC |
| host | Host where the event was recorded; canonicalize FQDN/short-name differences |
| channel | Security, System, or Microsoft-Windows-Sysmon/Operational |
| event_id | Numeric Windows event ID |
| account | Domain-qualified relevant account: target for 4624/4625/4648, subject for 4672; for process events record actual execution identity |
| source_host | Resolved source endpoint for logons; use timestamp-aware asset/DNS mapping from source_ip; never substitute collector host |
| source_ip | Optional original source address; retain for investigation |
| logon_type | Numeric or string logon type for 4624/4625 |
| logon_id | TargetLogonId for 4624; SubjectLogonId for 4672; normalize hexadecimal text |
| service_name | System 7045 ServiceName |
| service_account | Service execution identity from 7045; not assumed to be the installer |
| image / parent_image | Full process paths, normalized from 4688 or Sysmon 1 fields |
| synthetic | true for every included sample event |

4624 host is the destination; source_host is a separately resolved identity. A missing or unresolved source prevents chain construction. Hostname aliases and account aliases are not automatically merged. Account comparisons are case-insensitive but do not merge different domains.

Host + local logon ID + account + a short time interval is used for 4672 enrichment. IDs may be reused across reboots; preserve boot/session metadata when extending this demonstration to longer windows. Processes under SYSTEM and 7045 service accounts are deliberately not coerced to svc-backup.

For authentic evidence retain raw records separately, record collection hashes, then document every normalization decision. Real exports can contain sensitive data: review and redact before putting them in any repository. `.gitignore` excludes EVTX and `private-data/`; this is a convenience, not a complete data-loss safeguard.
