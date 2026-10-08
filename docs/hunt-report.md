# Hunt report · LM-001

**Status:** completed synthetic-data investigation. **Window:** 2026-10-08 09:00–10:12 UTC. **Scope:** illustrative LAB domain. **No production incident or containment is claimed.**

## Hypothesis

An operator used `LAB\svc-backup` to move from PC-01 to PC-02 with PsExec, then from PC-02 to FILE-01 with RDP. The account is designated non-interactive in the exercise's service-account inventory. The investigation asks whether telemetry supports the path and whether administrative context could explain it.

## Evidence timeline

| UTC | Record | Host | Observation | Interpretation |
|---|---|---|---|---|
| 10:01:00 | E01 | PC-01 | 4648, explicit credentials, target PC-02 | Supporting attempted credential use, not proof of success |
| 10:02:00 | E02 | PC-02 | 4624 type 3, svc-backup, source PC-01 | First observed network logon |
| 10:03:00 | E03 | PC-02 | System 7045, PSEXESVC, LocalSystem | PsExec-associated service installation; operator not identified by service account |
| 10:05:00 | E04, E05 | PC-02 | Security 4688 and Sysmon 1, cmd.exe child of PSEXESVC.exe | Two telemetry views of one synthetic process, not two executions |
| 10:11:00 | E06 | FILE-01 | 4624 type 10, svc-backup, source PC-02 | Second observed hop, RemoteInteractive session 0x201 |
| 10:11:01 | E07 | FILE-01 | 4672, svc-backup, session 0x201 | Special privileges associated with the same local session |

Elapsed time from first logon to RDP: **9 minutes**. E01 provides context but is not a required rule input. B01–B07 are benign or unrelated negative controls, including a deliberately reused logon ID on OTHER-01.

## Assessment

The synthetic scenario supports a **high-priority lateral-movement candidate**. RDP use conflicts with the assumed non-interactive purpose of svc-backup. However, the records alone do not prove malicious intent or conclusively attribute the intermediate LocalSystem process to that account. An approved administrative workflow is an alternative explanation. Determine whether the source hosts, operator and change request are authorized before assigning an incident verdict.

ATT&CK mapping: **T1021.002 SMB/Windows Admin Shares** (PsExec-associated first hop) and **T1021.001 Remote Desktop Protocol** (second hop). These describe behavior; mapping is not a maliciousness verdict. Event 4624 type 3 alone does not establish SMB use; in real data confirm ADMIN$ access and network evidence.

## Proposed response if confirmed unauthorized

1. Preserve original EVTX exports, timestamps, source identifiers and hashes. Record clock offsets and collection gaps.
2. Validate the service account owner, permitted hosts, approved jobs, maintenance windows and operator activity.
3. Escalate to the incident lead. Coordinate account containment with backup owners to avoid disrupting recovery operations.
4. Under the incident-response process, isolate affected hosts and revoke or rotate affected credentials. These actions were **not performed** by this project.
5. Hunt across other hosts for the account, remote logons, service creation, and process/network evidence. Review exposure before restoring access.

## Detection follow-up

Deploy a service-account RemoteInteractive alert backed by an authoritative inventory, then enrich with logon/session and source-host evidence. Tune approved activity by scoped account/host/time exceptions with an owner and expiry. Do not globally suppress PsExec or all administrator accounts. Measure false positives and missing telemetry using captured lab evidence before production use.

## Validation

The offline fixture expects 14 input records, one RDP alert, and one correlated chain alert. Unit tests check missing evidence, unrelated accounts/hosts/channels, window boundaries, local logon ID scope, case handling, malformed data and output files. The repository contains a live-lab runbook; that environment has not been executed here.
