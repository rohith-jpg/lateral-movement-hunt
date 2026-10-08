"""Exercise the actual CLI boundary, not just the correlation function."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from lateral_hunt.cli import main

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_fixture_end_to_end(self):
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                main(
                    [
                        "--input",
                        str(ROOT / "data/events.jsonl"),
                        "--service-accounts",
                        str(ROOT / "data/service_accounts.json"),
                        "--output",
                        directory,
                    ]
                )
            self.assertIn("14 events; 2 alerts", output.getvalue())
            self.assertEqual(len(json.loads((Path(directory) / "alerts.json").read_text())), 2)

    def test_invalid_input_returns_actionable_error(self):
        error = io.StringIO()
        with contextlib.redirect_stderr(error), self.assertRaises(SystemExit) as raised:
            main(["--input", str(ROOT / "data/does-not-exist.jsonl")])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("Error:", error.getvalue())

    def test_empty_dataset_is_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "empty.jsonl").write_text("", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                main(
                    [
                        "--input",
                        str(path / "empty.jsonl"),
                        "--service-accounts",
                        str(ROOT / "data/service_accounts.json"),
                        "--output",
                        str(path / "out"),
                    ]
                )
            self.assertEqual(json.loads((path / "out/alerts.json").read_text()), [])

    def test_invalid_inventory_returns_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "accounts.json"
            path.write_text('["unqualified"]', encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                main(["--input", str(ROOT / "data/events.jsonl"), "--service-accounts", str(path)])
            self.assertEqual(raised.exception.code, 2)
