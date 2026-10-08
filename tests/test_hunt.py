import copy
import json
import tempfile
import unittest
from pathlib import Path
from hunt import analyze, load_events, write_outputs

ROOT = Path(__file__).resolve().parents[1]


class HuntTests(unittest.TestCase):
    def setUp(self):
        self.events = load_events(ROOT / 'data/events.jsonl')
        self.accounts = ['LAB\\svc-backup']

    def chains(self, events=None, **kwargs):
        return [a for a in analyze(self.events if events is None else events, self.accounts, **kwargs)
                if a['rule'] == 'psexec_then_rdp_candidate']

    def test_expected_chain_and_context(self):
        chain, = self.chains()
        self.assertEqual(chain['path'], ['PC-01', 'PC-02', 'FILE-01'])
        self.assertEqual(chain['evidence'], ['E02', 'E03', 'E04', 'E05', 'E06', 'E07'])
        self.assertEqual(len(analyze(self.events, self.accounts)), 2)

    def test_benign_controls(self):
        self.assertEqual(analyze([e for e in self.events if e['event_uid'].startswith('B')], self.accounts), [])

    def test_missing_support_never_produces_chain(self):
        for removed in ({'E03'}, {'E04', 'E05'}, {'E02'}, {'E06'}):
            self.assertEqual(self.chains([e for e in self.events if e['event_uid'] not in removed]), [])

    def test_wrong_source_account_or_channel(self):
        for field, value in [('source_host', 'UNRELATED'), ('account', 'OTHER\\svc-backup'), ('channel', 'System')]:
            events = copy.deepcopy(self.events)
            next(e for e in events if e['event_uid'] == 'E06')[field] = value
            self.assertEqual(self.chains(events), [])

    def test_window_boundary(self):
        self.assertEqual(len(self.chains(window_minutes=9)), 1)
        self.assertEqual(self.chains(window_minutes=8), [])
        with self.assertRaises(ValueError):
            self.chains(window_minutes=0)

    def test_privileges_require_session_and_host(self):
        events = copy.deepcopy(self.events)
        next(e for e in events if e['event_uid'] == 'E07')['logon_id'] = '0x999'
        self.assertNotIn('E07', self.chains(events)[0]['evidence'])
        self.assertNotIn('B07', self.chains(events)[0]['evidence'])

    def test_case_insensitive_account(self):
        self.accounts = ['lab\\SVC-BACKUP']
        self.assertEqual(len(self.chains()), 1)

    def test_reverse_order_and_repeated_host(self):
        self.assertEqual(len(self.chains(list(reversed(self.events)))), 1)
        events = copy.deepcopy(self.events)
        next(e for e in events if e['event_uid'] == 'E06')['host'] = 'PC-01'
        self.assertEqual(self.chains(events), [])

    def test_bad_input_and_duplicate_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.jsonl'
            for content in ['{bad', '{}', json.dumps(dict(self.events[0], timestamp='2026-10-08T10:00:00')),
                            (json.dumps(self.events[0]) + '\n') * 2]:
                path.write_text(content, encoding='utf-8')
                with self.assertRaises(ValueError):
                    load_events(path)

    def test_output_files(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            write_outputs(self.events, analyze(self.events, self.accounts), out)
            self.assertEqual(len(json.loads((out / 'alerts.json').read_text())), 2)
            self.assertIn('PC-01', (out / 'summary.md').read_text(encoding='utf-8'))
            self.assertEqual(len((out / 'timeline.csv').read_text().splitlines()), 15)


if __name__ == '__main__':
    unittest.main()
