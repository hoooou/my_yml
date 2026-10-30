import copy
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import availability as a
from upload_fixture import verified_upload_precheck
import medium_speed as m
from medium_speed_fixture import verified_medium
from high_speed_fixture import verified_high
from tls_fixture import verified_tls


def record(id='n-a', country='US'):
    return {'id': id, 'entry': {'status': 'passed'}, 'app_tls': verified_tls(),
        'websites': {**{label: {'status': 'passed', 'round_count': 3, 'passed_count': 3,
            'median_elapsed_ms': 120, 'p95_elapsed_ms': 130, 'jitter_ms': 10} for label in a.OVERSEAS_SITES},
            'ClaudeTrace': {'status': 'passed', 'round_count': 1, 'passed_count': 1}},
        'exit': {'country_code': country, 'exit_ip': '8.8.8.8'},
        'download': {'status': 'passed', 'speed_mib_s': 1},
        'medium_speed_download': verified_medium(5),
        'ip_reputation': {'status': 'success', 'is_datacenter': False, 'company_type': 'isp',
                          'network_purity_score': 99.2}}


class MediumDownloadTests(unittest.TestCase):
    def test_live_download_caller_uses_5mb_budget_and_rejects_late_partial_or_bad_response(self):
        class Response:
            url = m.URL
            status_code = 200
            def __init__(self, byte_count=m.BYTES, header_length=m.BYTES, status=200):
                self.remaining = byte_count; self.status_code = status; self.raw = self
                self.headers = {'Content-Length': str(header_length), 'Content-Type': 'application/octet-stream'}
            def read1(self, size):
                count = min(size, self.remaining); self.remaining -= count
                return b'x' * count
            def __enter__(self): return self
            def __exit__(self, *args): pass
        for response, elapsed, expected in ((Response(), 2, 'passed'), (Response(), 10.001, 'failed'),
                (Response(m.BYTES-1), 2, 'failed'), (Response(header_length=1), 2, 'failed'),
                (Response(status=403), 2, 'failed')):
            with patch.object(a.s, 'session') as session, \
                 patch.object(a.time, 'perf_counter', side_effect=[0] + [elapsed]*1000):
                session.return_value.__enter__.return_value.get.return_value = response
                sample = a.medium_speed_download(1234)
                fetch = session.return_value.__enter__.return_value.get
            self.assertEqual(sample['status'], expected)
            self.assertEqual(m.passed(sample), expected == 'passed')
            self.assertEqual((sample['url'], sample['requested_bytes'], sample['budget_seconds']), (m.URL, m.BYTES, 10))
            self.assertEqual(fetch.call_args.kwargs['headers']['Referer'], 'https://speed.cloudflare.com/')

    def test_pipeline_orders_1mb_5mb_100mb_and_medium_failure_stops_before_sites(self):
        node = {'name': 'n-a', 'type': 'ss', 'server': '8.8.8.8', 'port': 443}
        pre = a.summarize_rounds([{'Google204': {'status': 'passed', 'elapsed_ms': 10}}]*3, ('Google204',))['Google204']
        # 1MB 不通过只跑 1MB；5MB 不通过就停在 5MB，后面网站、TLS、100MB 都不跑。
        for quick_ok, medium_ok, expected in ((True, True, ['1MB', '5MB', '100MB']),
                                              (True, False, ['1MB', '5MB']),
                                              (False, True, ['1MB'])):
            calls, sites = [], []
            with patch.object(a.s, 'Core'), patch.object(a.s, 'query_exit', return_value=None), \
                 patch.object(a.s, 'make_listeners', return_value=([], {'n-a': 1234})), \
                 patch.object(a.app_tls, 'check', return_value=verified_tls()):
                rows, _ = a.probe_pipeline([node], 'unused', Path('.'), precheck=lambda p: pre,
                    probe=lambda key, pace: {'status': 'passed'},
                    site_check=lambda p: sites.append(1) or {label: {'status': 'passed', 'elapsed_ms': 10} for label in a.POST_SITES},
                    download=lambda p: calls.append('1MB') or {'status': 'passed' if quick_ok else 'failed',
                        'received_bytes': a.DOWNLOAD_BYTES, 'elapsed_ms': 100},
                    medium_download=lambda p: calls.append('5MB') or
                        (verified_medium() if medium_ok else {**verified_medium(), 'status': 'failed'}),
                    large_download=lambda p: calls.append('100MB') or verified_high(), upload_precheck=verified_upload_precheck)
            self.assertEqual(calls, expected)
            self.assertEqual(bool(sites), quick_ok and medium_ok)
            part = {'bundle_id': 'batch', 'index': 0, 'count': 1, 'endpoint_count': 1, 'records': rows}
            bundle = {'id': 'batch', 'nodes': [node], 'website_tls_hard_gate': True}
            a.merge_shards(bundle, [part], 1)
            if quick_ok:
                rows[0]['medium_speed_download'].pop('requested_bytes')
                with self.assertRaisesRegex(ValueError, '5 MB'):
                    a.merge_shards(bundle, [part], 1)

    def test_medium_evidence_and_eligible_pool_required_without_limiting_non_hk(self):
        records = [record(f'n-{i}', 'HK' if i < 35 else 'US') for i in range(75)]
        mapping = {r['id']: {'name': r['id'], 'type': 'http', 'server': '8.8.8.8', 'port': 80} for r in records}
        bad = copy.deepcopy(records[-1]); bad['id'] = 'n-blocked'; bad['entry']['status'] = 'failed'
        records.append(bad); mapping[bad['id']] = mapping['n-74']
        cfg = a.render_comparison({}, records, mapping)
        group = next(g for g in cfg['proxy-groups'] if g['name'] == m.GROUP)
        self.assertEqual(len(group['proxies']), 70)  # HK30 + US40.
        self.assertNotIn('name', bad)
        for mutate in ('missing', 'old_100mb', 'partial', 'late', 'wrong_url', 'nan'):
            good = record()
            sample = good['medium_speed_download']
            if mutate == 'missing': good.pop('medium_speed_download')
            elif mutate == 'old_100mb': good['medium_speed_download'] = verified_high()
            elif mutate == 'partial': sample['received_bytes'] -= 1
            elif mutate == 'late': sample['elapsed_ms'] = 10001
            elif mutate == 'wrong_url': sample['url'] = a.DOWNLOAD_URL
            else: sample['speed_mib_s'] = float('nan')
            cfg = a.render_comparison({}, [good], {'n-a': mapping['n-74']})
            groups = {g['name']: g['proxies'] for g in cfg['proxy-groups']}
            self.assertEqual(groups[m.GROUP], ['REJECT'], mutate)
            self.assertEqual(len(cfg['proxies']), 1)  # General selection is preserved.

    def test_medium_group_includes_regional_only_node_after_5mb_pass(self):
        row = record(country='TW')
        row['precheck'] = {'status': 'passed', 'round_count': 3, 'passed_count': 3}
        for label in a.CORE_SITES:
            row['websites'][label].update(median_elapsed_ms=2500, p95_elapsed_ms=3000, jitter_ms=500)
        self.assertFalse(a.web_quality_eligible(row))
        self.assertTrue(a.regional_eligible(row))
        cfg = a.render_comparison({}, [row], {'n-a': {'name': 'n-a', 'type': 'http', 'server': '8.8.8.8', 'port': 80}})
        groups = {g['name']:g['proxies'] for g in cfg['proxy-groups']}
        self.assertEqual(groups[m.GROUP], [row['name']])
        self.assertEqual(groups[a.REGIONAL_GROUP], [row['name']])
        self.assertEqual(groups['⭐ 综合优选'], ['REJECT'])
        self.assertEqual(groups['⚡ 高速下载'], ['REJECT'])

    def test_names_exact_format_region_numbering_housing_unknown_and_speed_priority(self):
        rows = [record('n-b'), record('n-a'), record('n-c', 'JP')]
        rows[1]['ip_reputation'].update(is_datacenter=True)
        rows[2]['ip_reputation'] = {'status': 'unknown'}
        rows[2]['ip_type'] = {'status': 'success', 'hosting': False}
        rows[0]['high_speed_download'] = verified_high(10)
        mapping = {r['id']: {'name': r['id'], 'type': 'http', 'server': '8.8.8.8', 'port': 80} for r in rows}
        cfg = a.render_comparison({}, rows, mapping)
        byid = {r['id']:r['name'] for r in rows}
        self.assertEqual(byid['n-a'], '美国01|120ms|42Mbps|机房|纯净度99.2%')
        self.assertEqual(byid['n-b'], '美国02|120ms|84Mbps|住宅|纯净度99.2%')
        self.assertEqual(byid['n-c'], '日本01|120ms|42Mbps|未知|纯净度未知')
        self.assertEqual(len({n['name'] for n in cfg['proxies']}), 3)
        self.assertTrue(all(len(n['name'].split('|')) == 5 for n in cfg['proxies']))

    def test_pipeline_caps_medium_downloads_at_four_per_shard(self):
        nodes = [{'name': f'n-{i}', 'type': 'ss', 'server': '8.8.8.8', 'port': 443} for i in range(8)]
        lock = threading.Lock()
        state = {'active': 0, 'peak': 0}
        def medium(port):
            with lock:
                state['active'] += 1
                state['peak'] = max(state['peak'], state['active'])
            try:
                time.sleep(0.2)
            finally:
                with lock: state['active'] -= 1
            return verified_medium()
        with patch.object(a.s, 'Core'), patch.object(a.s, 'query_exit', return_value=None), \
             patch.object(a.s, 'make_listeners', return_value=([], {f'n-{i}': i for i in range(8)})), \
             patch.object(a.app_tls, 'check', return_value=verified_tls()):
            rows, _ = a.probe_pipeline(nodes, 'unused', Path('.'), precheck=lambda p: {'status': 'passed'},
                probe=lambda key, pace: {'status': 'passed'},
                site_check=lambda p: {label: {'status': 'passed', 'elapsed_ms': 10} for label in a.POST_SITES},
                download=lambda p: {'status': 'passed', 'received_bytes': a.DOWNLOAD_BYTES, 'elapsed_ms': 100},
                medium_download=medium,
                large_download=lambda p: verified_high(), upload_precheck=verified_upload_precheck)
        self.assertLessEqual(state['peak'], 4)
        self.assertGreaterEqual(state['peak'], 2)
        self.assertEqual(sum(m.passed(r['medium_speed_download']) for r in rows), 8)

    def test_supplement_only_existing_1mb_passed_nodes_preserves_other_measurements(self):
        rows = [record(), record('n-b'), record('n-unpublished')]
        rows[1]['download']['status'] = 'failed'
        for r in rows: r.pop('medium_speed_download')
        before = copy.deepcopy(rows)
        mapping = {r['id']: {'name': r['id']} for r in rows[:2]}
        with patch.object(a.s, 'Core'), patch.object(a.s, 'make_listeners', return_value=([], {'n-a': 1234})), \
             patch.object(a, 'medium_speed_download', return_value=verified_medium()) as measure:
            self.assertEqual(a.recheck_medium_download(rows, mapping, 'unused', Path('.')), 1)
        measure.assert_called_once_with(1234)
        self.assertEqual(rows[1:], before[1:])
        self.assertEqual({k:v for k,v in rows[0].items() if k not in ('medium_speed_download','medium_speed_updated_at')}, before[0])
