# Hunt results

Triage candidates, not a determination of malicious intent.

Events: 14 | Alerts: 2

## service_account_rdp (medium)

Account: `LAB\svc-backup`

Configured service account used for RemoteInteractive logon; review authorization.

Evidence: E06

## psexec_then_rdp_candidate (high)

Account: `LAB\svc-backup`

Same-account two-hop logons plus intermediate-host PsExec artifacts. Service/process timing is circumstantial; confirm operator and session attribution.

Evidence: E02, E03, E04, E05, E06, E07

Path: PC-01 → PC-02 → FILE-01
