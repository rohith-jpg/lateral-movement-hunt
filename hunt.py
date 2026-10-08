"""Offline Windows lateral-movement triage. Python 3.10+, standard library only."""
import argparse
import csv
import json
from datetime import datetime
from pathlib import Path


def timestamp(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('timestamps must include a timezone')
    return result


def load_events(path):
    events = []
    seen = set()
    with Path(path).open(encoding='utf-8-sig') as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                for field in ('event_uid', 'timestamp', 'event_id', 'host', 'channel'):
                    if field not in event:
                        raise ValueError(f'missing {field}')
                timestamp(event['timestamp'])
                event['event_id'] = int(event['event_id'])
                if not all(isinstance(event[k], str) and event[k] for k in ('event_uid', 'host', 'channel')):
                    raise ValueError('event_uid, host and channel must be nonempty strings')
                if event['event_uid'] in seen:
                    raise ValueError('duplicate event_uid')
                seen.add(event['event_uid'])
                events.append(event)
            except (ValueError, TypeError, KeyError) as error:
                raise ValueError(f'{path}:{line_number}: {error}') from error
    return sorted(events, key=lambda e: (timestamp(e['timestamp']), e['event_uid']))


def same(left, right):
    return bool(left and right) and str(left).casefold() == str(right).casefold()


def analyze(events, service_accounts, window_minutes=15):
    """Correlate two logons; local service/process evidence is supporting, not attribution."""
    if window_minutes <= 0:
        raise ValueError('window_minutes must be positive')
    services = {a.casefold() for a in service_accounts}
    logons = [e for e in events if e['channel'] == 'Security' and e['event_id'] == 4624]
    alerts = []
    for remote in logons:
        if str(remote.get('logon_type')) != '10' or remote.get('account', '').casefold() not in services:
            continue
        alerts.append({'rule': 'service_account_rdp', 'severity': 'medium',
                       'account': remote['account'], 'evidence': [remote['event_uid']],
                       'reason': 'Configured service account used for RemoteInteractive logon; review authorization.'})
        for first in logons:
            if str(first.get('logon_type')) != '3' or not same(first.get('account'), remote.get('account')):
                continue
            delta = (timestamp(remote['timestamp']) - timestamp(first['timestamp'])).total_seconds()
            if not 0 < delta <= window_minutes * 60:
                continue
            if not same(remote.get('source_host'), first['host']):
                continue
            path = [first.get('source_host'), first['host'], remote['host']]
            if not all(path) or len({p.casefold() for p in path}) != 3:
                continue
            middle = [e for e in events if same(e['host'], first['host'])
                      and timestamp(first['timestamp']) <= timestamp(e['timestamp']) <= timestamp(remote['timestamp'])]
            installs = [e for e in middle if e['channel'] == 'System' and e['event_id'] == 7045
                        and same(e.get('service_name'), 'PSEXESVC')]
            processes = [e for e in middle if ((e['channel'] == 'Security' and e['event_id'] == 4688)
                         or (e['channel'] == 'Microsoft-Windows-Sysmon/Operational' and e['event_id'] == 1))
                         and e.get('parent_image', '').replace('/', '\\').casefold().endswith('\\psexesvc.exe')]
            if not installs or not processes:
                continue
            privileges = [e for e in events if e['channel'] == 'Security' and e['event_id'] == 4672
                          and same(e['host'], remote['host']) and same(e.get('account'), remote.get('account'))
                          and same(e.get('logon_id'), remote.get('logon_id'))
                          and 0 <= (timestamp(e['timestamp']) - timestamp(remote['timestamp'])).total_seconds() <= 120]
            evidence = [first] + installs + processes + [remote] + privileges
            alerts.append({'rule': 'psexec_then_rdp_candidate', 'severity': 'high', 'account': remote['account'],
                           'path': path, 'start': first['timestamp'], 'end': remote['timestamp'],
                           'evidence': [e['event_uid'] for e in sorted(evidence, key=lambda e: timestamp(e['timestamp']))],
                           'attack': ['T1021.002', 'T1021.001'],
                           'reason': 'Same-account two-hop logons plus intermediate-host PsExec artifacts. '
                                     'Service/process timing is circumstantial; confirm operator and session attribution.'})
    return alerts


def write_outputs(events, alerts, out):
    out.mkdir(parents=True, exist_ok=True)
    (out / 'alerts.json').write_text(json.dumps(alerts, indent=2) + '\n', encoding='utf-8')
    fields = ['event_uid', 'timestamp', 'host', 'channel', 'event_id', 'account', 'source_host', 'logon_type', 'logon_id', 'service_name', 'image', 'parent_image']
    with (out / 'timeline.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(events)
    lines = ['# Hunt results', '', 'Triage candidates, not a determination of malicious intent.', '',
             f'Events: {len(events)} | Alerts: {len(alerts)}', '']
    for alert in alerts:
        lines += [f"## {alert['rule']} ({alert['severity']})", '', f"Account: `{alert['account']}`", '', alert['reason'], '',
                  'Evidence: ' + ', '.join(alert['evidence']), '']
        if 'path' in alert:
            lines += ['Path: ' + ' → '.join(alert['path']), '']
    (out / 'summary.md').write_text('\n'.join(lines), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=Path('data/events.jsonl'))
    parser.add_argument('--service-accounts', type=Path, default=Path('data/service_accounts.json'))
    parser.add_argument('--output', type=Path, default=Path('results'))
    parser.add_argument('--window-minutes', type=int, default=15)
    args = parser.parse_args()
    try:
        events = load_events(args.input)
        accounts = json.loads(args.service_accounts.read_text(encoding='utf-8'))
        if not isinstance(accounts, list) or not all(isinstance(a, str) for a in accounts):
            raise ValueError('service accounts must be a JSON list of domain-qualified names')
        alerts = analyze(events, accounts, args.window_minutes)
        write_outputs(events, alerts, args.output)
    except (OSError, ValueError) as error:
        parser.exit(2, f'Error: {error}\n')
    print(f'Analyzed {len(events)} events; {len(alerts)} alerts written to {args.output}')


if __name__ == '__main__':
    main()
