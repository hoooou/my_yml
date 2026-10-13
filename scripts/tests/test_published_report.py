import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import published_report as p


class PublishedReportTests(unittest.TestCase):
    def fixture(self):
        report = {'source_run': '123', 'published_node_ids': ['n-a'],
                  'measurements_updated_at': '2026-10-13T13:44:04+08:00',
                  'entry_counts': {'passed': 2, 'failed': 5},
                  'nodes': [{'id': 'n-a', 'name': '香港01', 'sources': ['public'],
                             'stability': {'attempts': [{'status': 'failed'}]}},
                            {'id': 'n-b', 'precheck': {'attempts': [1, 2, 3]}}]}
        raw = json.dumps(report, ensure_ascii=False).encode()
        return report, raw, p.repository_summary(report, raw, '123')

    def test_repository_keeps_counts_and_history_mapping_without_request_records(self):
        report, raw, summary = self.fixture()
        self.assertEqual(summary['entry_counts'], report['entry_counts'])
        self.assertEqual(summary['raw_record_count'], 2)
        self.assertEqual(summary['nodes'], [{'id': 'n-a', 'name': '香港01', 'sources': ['public']}])
        self.assertNotIn('attempts', json.dumps(summary))
        self.assertEqual(summary['raw_evidence']['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertIn('stability', report['nodes'][0])

    def test_cached_raw_evidence_is_verified_before_rechecks(self):
        report, raw, summary = self.fixture()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root / '123').mkdir()
            path = root / '123' / p.FILENAME; path.write_bytes(raw)
            self.assertEqual(p.load_report(summary, root), report)
            path.write_bytes(raw + b' ')
            with self.assertRaises(ValueError): p.load_report(summary, root)

    def test_old_raw_reports_remain_compatible_and_unsafe_artifact_refs_fail(self):
        report, raw, summary = self.fixture()
        self.assertIs(p.load_report(report), report)
        summary['raw_evidence']['run_id'] = '../bad'
        with self.assertRaises(ValueError): p.load_report(summary)


if __name__ == '__main__':
    unittest.main()
