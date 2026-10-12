import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import latest_report as latest
from test_detection_report import fixture


class LatestReportTests(unittest.TestCase):
    def test_failure_reasons_never_claim_a_measured_request_was_skipped(self):
        items = [{'status': 'failed', 'attempts': [{'status': 'failed', 'reason': '连接、TLS 或读取失败'}]},
                 {'status': 'skipped'}]
        result = latest.counts('204', '204三轮', items, lambda x: x.get('status') == 'passed', '未进行204检测')
        reasons = {r['status']: r['reason'] for r in result['reason_counts']}
        self.assertEqual(reasons['failed'], '连接、TLS 或读取失败')
        self.assertEqual(reasons['skipped'], '未进行204检测')

    def test_zero_attempt_records_every_stage_without_overwriting_old_subscription(self):
        report, config = fixture()
        report.update(publication_mode='full', published_node_ids=[], selected_node_count=0,
                      parseable_count=3, input_unique_count=5)
        config['proxies'] = []
        for row in report['nodes']:
            row.pop('service_checks', None)
            row['entry'] = {'status': 'unknown', 'attempts': 0, 'reason': '204未过，未提交TCP'}
            row['download'] = {'status': 'skipped', 'reason': '必过网站未通过'}
            row['websites'] = {}
        original = copy.deepcopy(report)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'README.md').write_text('# Manual guide\n' + latest.replace_fragment('', 'old report'))
            old = json.dumps({'published_node_count': 17, 'measurements_updated_at': '2026-10-12T12:13:29+08:00'})
            (root/'连通性报告.json').write_text(old)
            (root/'优选配置.yaml').write_text('old subscription')
            value = latest.write_latest(report, config, root, candidate=True, validation='skipped_no_candidates')
            text = (root/'README.md').read_text()
            self.assertIn('Manual guide', text)
            self.assertNotIn('old report', text)
            self.assertIn('本轮无合格节点，保留原订阅', text)
            self.assertIn('原订阅的 **17** 个节点', text)
            for label in ('FAST API', 'FAST CDN 1', 'FAST CDN 2', 'FAST CDN 3',
                          'Cloudflare 100MB', 'DataPacket 100MB', '最终配置校验'):
                self.assertIn(label, text)
            self.assertEqual((root/'优选配置.yaml').read_text(), 'old subscription')
            self.assertEqual((root/'连通性报告.json').read_text(), old)
            self.assertNotIn('nodes', value)
            stages = {x['id']: x for x in value['stage_summary']}
            self.assertEqual(stages['tcp']['skipped'], 3)
            self.assertEqual(stages['tcp']['unverified'], 0)
            self.assertEqual(stages['parse']['failed'], 2)
            self.assertEqual(stages['fast_cdn_3']['skipped'], 3)
            self.assertEqual(stages['config_validation']['skipped'], 1)
        self.assertEqual(report, original)

    def test_latest_refresh_never_replaces_new_zero_attempt_with_old_published_measurements(self):
        from refresh_detection_report import refresh
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'连通性报告.json').write_text('{"updated_at":"old"}')
            (root/'最新检测.json').write_text('{"updated_at":"new","selected_node_count":0}')
            (root/'README.md').write_text('latest zero attempt')
            refresh(root)
            self.assertEqual((root/'README.md').read_text(), 'latest zero attempt')
            self.assertIn('"new"', (root/'最新检测.json').read_text())

    def test_malformed_passed_config_never_claims_verified_and_manual_tail_survives(self):
        report, config = fixture()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'README.md').write_text('before\n'+latest.replace_fragment('', 'old')+'\nafter')
            result = latest.write_latest(report, config, root, validation='failed', candidate=True)
            stage = next(x for x in result['stage_summary'] if x['id'] == 'config_validation')
            self.assertEqual((stage['passed'], stage['failed']), (0, 1))
            text = (root/'README.md').read_text()
            self.assertTrue(text.startswith('before\n'))
            self.assertTrue(text.endswith('\nafter'))


if __name__ == '__main__':
    unittest.main()
