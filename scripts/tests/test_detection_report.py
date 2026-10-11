import copy
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import detection_report as d
import upload_speed as up
from test_medium_speed import record
from test_upload_speed import evidence as upload_evidence
from test_stability import evidence as stable_evidence
from tls_fixture import verified_tls


def fixture():
    selected = record('n-good'); selected.update(name='美国01|120ms|85Mbps|住宅|纯净度99.2%',
        upload=upload_evidence(), stability=stable_evidence(), post_upload_tls=verified_tls(),
        server='PRIVATE_SERVER', password='PRIVATE_PASSWORD')
    excluded = record('n-bad'); excluded['upload'] = upload_evidence()
    excluded['upload']['attempts'][1].update(status='failed', curl_exit_code=28)
    excluded['stability'] = stable_evidence(); excluded['post_upload_tls'] = verified_tls()
    old = record('n-historical'); old['stability'] = {'status': 'failed'}
    report = {'nodes': [selected, excluded, old], 'publication_mode': 'repair',
        'updated_at': '2026-10-12T06:00:00+08:00', 'measurements_updated_at': '2026-10-12T01:00:00+08:00',
        'published_node_ids': ['n-good'], 'published_node_count': 1,
        'upload_recheck': {'updated_at': '2026-10-12T05:00:00+08:00', 'node_ids': ['n-good', 'n-bad']},
        'stability_recheck': {'updated_at': '2026-10-12T05:05:00+08:00', 'node_ids': ['n-good', 'n-bad']}}
    config = {'proxies': [{'name': selected['name']}], 'proxy-groups': [
        {'name': '🚀 全局选择', 'proxies': ['⭐ 综合优选', 'DIRECT']},
        {'name': '⭐ 综合优选', 'proxies': [selected['name']]},
        {'name': '⚡ 高速下载', 'proxies': ['REJECT']}]}
    return report, config


def render(report, config, **kwargs):
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / 'report.md'
        d.write_report(report, config, path, **kwargs)
        return path.read_text()


class CleanReportTests(unittest.TestCase):
    def test_latest_cohort_excludes_historical_failures_and_private_fields(self):
        report, config = fixture(); text = render(report, config)
        self.assertIn('覆盖 **2** 个节点', text)
        self.assertIn('| 美国01 | 100 / 0 |', text)
        self.assertIn('5MB上传请求超时', text)
        for value in ('n-historical', 'PRIVATE_SERVER', 'PRIVATE_PASSWORD', '请求响应质量', '手机对照'):
            self.assertNotIn(value, text)
        self.assertLess(len(text.splitlines()), 100)

    def test_rebuild_distinguishes_report_clock_from_actual_measurements(self):
        report, config = fixture(); text = render(report, config)
        self.assertIn('没有重新测速', text)
        for value in ('10-12 06:00:00', '10-12 01:00:00', '10-12 05:00:00', '10-12 05:05:00'):
            self.assertIn(value, text)
        self.assertEqual(d.clock('2026-10-11T21:00:00+00:00'), '10-12 05:00:00')

    def test_group_totals_count_only_real_nodes_and_warn_about_overlap(self):
        report, config = fixture(); text = render(report, config)
        self.assertEqual(d.group_counts(config), [('⭐ 综合优选', 1), ('⚡ 高速下载', 0)])
        self.assertIn('不能将数量相加', text)

    def test_cached_pass_status_does_not_show_ssl_or_stability_as_verified(self):
        report, config = fixture()
        row = report['nodes'][0]
        row['stability']['attempts'][4]['sites']['YouTube']['status'] = 'failed'
        row['post_upload_tls']['targets']['chatgpt.com']['attempts'][0]['hostname_verified'] = False
        row['upload']['attempts'][0]['uploaded_bytes'] -= 1
        line = next(x for x in render(report, config).splitlines() if x.startswith('| 美国01'))
        self.assertIn('未验证／需复核', line)
        self.assertNotIn('5/5', line)
        self.assertNotIn('20.0', line)

    def test_zero_candidate_full_run_is_clear_and_does_not_claim_publication(self):
        report, config = fixture(); report.update(publication_mode='full', published_node_ids=[],
            input_unique_count=5555, parseable_count=3)
        config['proxies'] = []
        text = render(report, config, candidate=True, website_gate=lambda r: True)
        self.assertIn('待发布候选：0', text)
        self.assertIn('本轮无合格节点，保留原订阅', text)
        self.assertIn('去重 **5555**', text)
        self.assertIn('12站＋Claude trace', text)

    def test_upload_summary_recomputes_current_cohort_without_old_failures(self):
        report, _ = fixture()
        previous = {**report['upload_recheck'], 'passed_count': 2}
        fresh = up.recheck_summary(report['nodes'], previous=previous)
        self.assertEqual((fresh['node_count'], fresh['passed_count'], fresh['failed_count']), (2, 1, 1))
        bad = copy.deepcopy(previous); bad['node_ids'].append('missing')
        with self.assertRaisesRegex(ValueError, '缺少'):
            up.recheck_summary(report['nodes'], previous=bad)
