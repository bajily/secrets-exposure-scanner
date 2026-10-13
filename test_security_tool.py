import copy
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import security_tool as tool

NOW = datetime(2026, 10, 13, 12, tzinfo=timezone.utc)


class ReportingTests(unittest.TestCase):
    def test_demo_generates_explainable_findings(self):
        results = tool.audit(copy.deepcopy(tool.DEMO), {}, NOW)
        self.assertTrue(results)
        self.assertTrue(all(item['remediation'] and item['evidence'] for item in results))

    def test_fingerprints_are_deterministic(self):
        self.assertEqual(tool.audit(copy.deepcopy(tool.DEMO), {}, NOW),
                         tool.audit(copy.deepcopy(tool.DEMO), {}, NOW))

    def test_active_and_expired_suppressions(self):
        rows = tool.audit(copy.deepcopy(tool.DEMO), {}, NOW)
        item = {'fingerprint': rows[0]['fingerprint'], 'reason': 'Synthetic exception review',
                'expires': '2027-01-01T00:00:00Z'}
        self.assertEqual(len(tool.build_report(rows, [item], NOW)['suppressed']), 1)
        item['expires'] = '2026-01-01T00:00:00Z'
        self.assertEqual(len(tool.build_report(rows, [item], NOW)['suppressed']), 0)

    def test_invalid_exception_and_input(self):
        with self.assertRaises(ValueError):
            tool.build_report([], [{'fingerprint': 'x', 'reason': '', 'expires': 'bad'}], NOW)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            tool.audit({}, {}, NOW)
        duplicate = {'fingerprint': 'same', 'reason': 'Synthetic test exception', 'expires': '2027-01-01T00:00:00Z'}
        with self.assertRaises(ValueError):
            tool.build_report([], [duplicate, duplicate], NOW)

    def test_json_ambiguity_rejected(self):
        for content in ['{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}']:
            with self.assertRaises(ValueError):
                tool.decode_json(content)

    def test_sarif_contains_rules_and_stable_fingerprints(self):
        report = tool.build_report(tool.audit(copy.deepcopy(tool.DEMO), {}, NOW), now=NOW)
        result = tool.sarif(report)
        self.assertEqual(result['version'], '2.1.0')
        self.assertEqual(len(result['runs'][0]['results']), len(report['findings']))
        self.assertTrue(all(x['partialFingerprints'] for x in result['runs'][0]['results']))

    def test_cli_demo_and_missing_input(self):
        script = Path(__file__).with_name('security_tool.py')
        result = subprocess.run([sys.executable, str(script), '--demo', '--now', NOW.isoformat()],
                                capture_output=True, text=True)
        self.assertIn(result.returncode, [0, 1], result.stderr)
        self.assertEqual(json.loads(result.stdout)['tool'], tool.TOOL)
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)

class SecretTests(unittest.TestCase):
    def test_multiple_same_line_matches_have_one_fingerprint(self):
        data = {'documents': [{'path': 'x', 'text': 'AKIAABCDEFGHIJKLMNOP AKIAQRSTUVWXYZABCDEF'}]}
        rows = tool.audit(data, {}, NOW)
        self.assertEqual(len(rows), 1)

    def test_matches_never_printed(self):
        encoded = json.dumps(tool.audit(copy.deepcopy(tool.DEMO), {}, NOW))
        self.assertNotIn('AKIAABCDEFGHIJKLMNOP', encoded)
        self.assertNotIn('aB7x9Q2n4T6m8R0p3Z5v1H7k', encoded)
        self.assertIn('[REDACTED]', encoded)

    def test_low_entropy_placeholder_ignored(self):
        data = {'documents': [{'path': 'x', 'text': 'password = "aaaaaaaaaaaaaaaaaaaa"'}]}
        self.assertEqual(tool.audit(data, {}, NOW), [])

    def test_local_files_symlinks_and_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'settings').write_text(tool.DEMO['documents'][0]['text'])
            (root / 'binary').write_bytes(b'\0\xff')
            try:
                (root / 'link').symlink_to(root / 'settings')
            except OSError:
                pass
            rows = tool.audit({'root': str(root)}, {}, NOW)
            self.assertFalse(any(x['resource'] == 'link' for x in rows))
            self.assertTrue(any(x['rule'] == 'SECRET-INSPECTION-GAP' for x in rows))

    def test_exclusion(self):
        self.assertEqual(tool.audit(copy.deepcopy(tool.DEMO), {'exclude': ['src/**']}, NOW), [])

    def test_size_limit_reported(self):
        rows = tool.audit(copy.deepcopy(tool.DEMO), {'maximum_file_bytes': 10}, NOW)
        self.assertEqual(rows[0]['rule'], 'SECRET-INSPECTION-GAP')

    def test_entropy_boundaries(self):
        self.assertEqual(tool.entropy(''), 0)
        self.assertEqual(tool.entropy('aaaa'), 0)
        self.assertEqual(tool.entropy('abcd'), 2)


if __name__ == "__main__":
    unittest.main()
