import copy
import io
import json
import os
from pathlib import Path
import sys
import threading
import tempfile
import unittest
import yaml
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import availability as a


class AvailabilityTests(unittest.TestCase):
    def test_quick_download_requires_full_uncompressed_file_and_deadline(self):
        class Response:
            status_code = 200
            url = a.DOWNLOAD_URL
            def __init__(self, body, length=None, encoding='identity'):
                self.raw = io.BytesIO(body)
                self.headers = {'Content-Length': str(a.DOWNLOAD_BYTES if length is None else length),
                                'Content-Type': 'application/octet-stream', 'Content-Encoding': encoding}
            def __enter__(self): return self
            def __exit__(self, *args): pass
        complete = b'x' * a.DOWNLOAD_BYTES
        for body, length, encoding, expected in [(complete, None, 'identity', 'passed'),
                (complete[:-1], None, 'identity', 'failed'), (complete, 10, 'identity', 'failed'),
                (complete, None, 'gzip', 'failed')]:
            with patch.object(a.s, 'session') as session, patch.object(a.time, 'perf_counter', side_effect=[0] + [1]*1000):
                session.return_value.__enter__.return_value.get.return_value = Response(body, length, encoding)
                result = a.quick_download(1234)
            self.assertEqual(result['status'], expected)
            if expected == 'passed':
                self.assertEqual(result['received_bytes'], a.DOWNLOAD_BYTES)
                self.assertAlmostEqual(result['speed_mib_s'], a.DOWNLOAD_BYTES / 1048576, places=3)
            else: self.assertIsNone(result['speed_mib_s'])
        with patch.object(a.s, 'session') as session, patch.object(a.time, 'perf_counter', side_effect=[0, 7, 7]):
            session.return_value.__enter__.return_value.get.return_value = Response(complete)
            result = a.quick_download(1234)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['received_bytes'], 0)

    def test_repair_preserves_measurements_and_never_retests_network(self):
        good = {'name': 'good', 'type': 'trojan', 'server': 'example.com', 'port': 443, 'password': 'same'}
        bad = {**good, 'name': 'bad', 'sni': 'bad\x9f'}
        records = [{'id': ident, 'name': name, 'server': 'example.com', 'port': 443,
                    'protocol': 'trojan', 'entry': {'status': 'unknown'}, 'websites': None,
                    'exit': None, 'ip_type': {'status': 'unknown'}} for ident, name in [('n-a', 'good'), ('n-b', 'bad')]]
        report = {'updated_at': '2026-10-09T22:01:27+08:00', 'scope': 'all_subscriptions',
                  'nodes': records, 'sources': [], 'services': {}, 'input_unique_count': 2,
                  'invalid_node_ids': [], 'parallel_shards': 4}
        with tempfile.TemporaryDirectory() as directory:
            old_cwd = os.getcwd()
            try:
                os.chdir(directory)
                a.s.dump(Path('聚合配置.yaml'), {'rules': ['MATCH,🚀 全局选择']})
                a.s.dump(Path('优选配置.yaml'), {'proxies': [good, bad]})
                Path('连通性报告.json').write_text(json.dumps(report))
                with patch.object(sys, 'argv', ['availability', '--phase', 'repair', '--mihomo', 'unused']), \
                     patch.object(a, 'probe_pipeline', side_effect=AssertionError('no network retest')), \
                     patch.object(a.s, 'lookup_ip_types', side_effect=AssertionError('no IP retest')), \
                     patch.object(a.subprocess, 'run') as run:
                    run.return_value.returncode = 0
                    a.main()
                result = json.loads(Path('连通性报告.json').read_text())
                config = yaml.safe_load(Path('优选配置.yaml').read_text())
                self.assertEqual(result['measurements_updated_at'], report['updated_at'])
                self.assertEqual(result['nodes'][0]['entry'], records[0]['entry'])
                self.assertEqual(result['invalid_node_ids'], ['n-b'])
                self.assertEqual(result['parseable_count'], 1)
                self.assertEqual(config['proxies'][0]['password'], 'same')
                self.assertEqual(result['parallel_shards'], 4)
            finally:
                os.chdir(old_cwd)

    def test_publication_rejects_controls_even_when_source_yaml_escaped_them(self):
        record = {'id': 'n-a', 'entry': {'status': 'unknown'}, 'websites': None, 'exit': None}
        original = {'name': 'n-a', 'type': 'trojan', 'server': 'example.com', 'port': 443,
                    'password': 'unchanged', 'sni': 'https://t.me/wangcai2\xf0\x9f\x87'}
        decoded = yaml.safe_load(yaml.safe_dump(original))
        self.assertEqual(decoded, original)
        with self.assertRaises(ValueError):
            a.render_comparison({'rules': ['MATCH,🚀 全局选择']}, [record], {'n-a': decoded})

    def test_mobile_filter_drops_corrupt_nodes_without_rewriting_credentials(self):
        good = {'name': 'n-good', 'type': 'trojan', 'server': 'example.com', 'port': 443,
                'password': '中文🔑', 'sni': 'example.com'}
        bad = {**good, 'name': 'n-bad', 'sni': 'bad\x9f\x87'}
        nested = {**good, 'name': 'n-nested', 'ws-opts': {'headers': {'Host': 'bad\x00'}}}
        retained, rejected = a.filter_mobile_nodes([good, bad, nested])
        self.assertEqual(retained, [good])
        self.assertEqual(set(rejected), {'n-bad', 'n-nested'})
        self.assertEqual(rejected['n-bad'], ['sni'])
        self.assertEqual(good['password'], '中文🔑')

    def test_shards_cover_all_nodes_and_keep_shared_endpoints_together(self):
        nodes = [{'name': f'n-{i}', 'type': 'ss', 'server': f'8.8.8.{i // 2}', 'port': 443} for i in range(20)]
        parts = [a.shard_nodes(nodes, i, 4) for i in range(4)]
        self.assertEqual(sorted(n['name'] for p in parts for n in p), sorted(n['name'] for n in nodes))
        locations = {n['name']: i for i, p in enumerate(parts) for n in p}
        for i in range(0, 20, 2):
            self.assertEqual(locations[f'n-{i}'], locations[f'n-{i + 1}'])

    def test_merge_rejects_missing_duplicate_wrong_batch_and_incomplete_stages(self):
        nodes = [{'name': f'n-{i}', 'type': 'ss', 'server': f'8.8.8.{i}', 'port': 443} for i in range(20)]
        bundle = {'id': 'batch', 'nodes': nodes}
        pre = a.summarize_rounds([{'Google204': {'status': 'passed', 'elapsed_ms': 20}}] * 3, ('Google204',))['Google204']
        parts = [{'bundle_id': 'batch', 'index': i, 'count': 4, 'endpoint_count': len(a.shard_nodes(nodes, i, 4)),
                  'records': [{'id': n['name'], 'precheck': copy.deepcopy(pre), 'entry': {'status': 'failed'}, 'websites': None,
                               'download': {'status': 'skipped'}} for n in a.shard_nodes(nodes, i, 4)]} for i in range(4)]
        records, endpoints = a.merge_shards(bundle, parts, 4)
        self.assertEqual([r['id'] for r in records], [n['name'] for n in nodes])
        self.assertEqual(endpoints, 20)
        broken = [parts[:-1]]
        wrong = copy.deepcopy(parts); wrong[0]['bundle_id'] = 'old'; broken.append(wrong)
        wrong = copy.deepcopy(parts); wrong[0]['records'].append(wrong[0]['records'][0]); broken.append(wrong)
        wrong = copy.deepcopy(parts); wrong[0]['records'][0]['entry']['status'] = 'passed'; broken.append(wrong)
        wrong = copy.deepcopy(parts); wrong[0]['records'][0]['precheck']['attempts'].pop(); broken.append(wrong)
        wrong = copy.deepcopy(parts); wrong[0]['records'][0]['download'] = {'status': 'passed', 'received_bytes': 10}; broken.append(wrong)
        for case in broken:
            with self.assertRaises(ValueError): a.merge_shards(bundle, case, 4)

    def test_node_stages_overlap_but_each_node_preserves_order_and_shared_tcp_dedup(self):
        website_started = threading.Event(); events = []; tested = []
        nodes = [{'name': f'n-{i}', 'type': 'ss', 'server': '8.8.8.8', 'port': 443} for i in range(3)]
        def precheck(port):
            if port == 3:
                self.assertTrue(website_started.wait(1), '其他节点的后续检测等待了全量204完成')
            events.append(('204', port))
            return {'status': 'failed' if port == 3 else 'passed', 'round_count': 3, 'attempts': [{}]*3}
        def tcp(key, pace):
            self.assertIn(('204', 1), events)
            tested.append(key)
            return {'status': 'passed'}
        def websites(port):
            website_started.set(); events.append(('websites', port))
            return {label: {'status': 'passed', 'elapsed_ms': 1} for label in a.POST_SITES}
        def download(port):
            self.assertIn(('websites', port), events)
            events.append(('download', port)); return {'status': 'passed', 'speed_mib_s': 1}
        with patch.object(a.s, 'Core'), patch.object(a.s, 'make_listeners', return_value=([], {'n-0': 1, 'n-1': 2, 'n-2': 3})), \
             patch.object(a.s, 'query_exit', return_value={'exit_ip': '8.8.8.8', 'country_code': 'US'}):
            records, endpoints = a.probe_pipeline(nodes, 'unused', Path('.'), probe=tcp, precheck=precheck, site_check=websites, download=download)
        self.assertEqual(tested, [('8.8.8.8', 443)])
        self.assertEqual(endpoints, 1)
        self.assertEqual(records[0]['websites']['Google']['round_count'], 1)
        self.assertIsNone(records[2]['websites'])
        self.assertEqual(records[2]['entry']['status'], 'unknown')
        self.assertEqual(records[2]['entry']['attempts'], 0)
        self.assertNotIn(('download', 3), events)

    def test_three_204_rounds_are_independent_and_all_required(self):
        with patch.object(a, 'check_site', side_effect=[{'status': 'passed', 'elapsed_ms': 5}, {'status': 'failed'}, {'status': 'passed', 'elapsed_ms': 10}]) as check:
            result = a.precheck_204(1234)
        self.assertEqual(check.call_count, 3)
        self.assertEqual(result['status'], 'unstable')
        self.assertEqual(result['passed_count'], 2)

    def test_tcp_connection_failure_is_distinct_from_api_errors(self):
        self.assertEqual(a.parse_xxapi({'code': -2, 'msg': '连接失败'}, 'example.com', 443)['status'], 'failed')
        for data in [None, [], {'code': 500, 'msg': 'error'}, {'code': -2, 'msg': 'quota'},
                     {'code': 200, 'data': {'address': 'other.com', 'port': 443, 'ping': '2ms'}},
                     {'code': 200, 'data': {'address': 'example.com', 'port': 80, 'ping': '2ms'}},
                     {'code': 200, 'data': {'address': 'example.com', 'port': 443, 'ping': 'NaNms'}}]:
            self.assertEqual(a.parse_xxapi(data, 'example.com', 443)['status'], 'unknown')
        result = a.parse_xxapi({'code': 200, 'data': {'address': 'example.com', 'port': '443', 'ping': '21ms'}}, 'example.com', 443)
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(result['latency_ms'], 21)

    def test_all_unique_tcp_endpoints_tested_and_shared_credentials_not_dropped(self):
        nodes = [{'name': 'n-1', 'type': 'ss', 'server': '8.8.8.8', 'port': 443, 'password': 'a'},
                 {'name': 'n-2', 'type': 'ss', 'server': '8.8.8.8', 'port': 443, 'password': 'b'},
                 {'name': 'n-3', 'type': 'ss', 'server': '1.1.1.1', 'port': 80},
                 {'name': 'n-4', 'type': 'hysteria2', 'server': '1.1.1.1', 'port': 443}]
        tested = []
        def probe(key, pace):
            tested.append(key)
            return {'status': 'passed' if key[1] == 443 else 'failed'}
        records, count = a.classify_all(nodes, probe=probe)
        self.assertEqual(set(tested), {('8.8.8.8', 443), ('1.1.1.1', 80)})
        self.assertEqual(count, 2)
        self.assertEqual(len(records), 4)
        self.assertEqual([r['entry']['status'] for r in records], ['passed', 'passed', 'failed', 'unknown'])

    def test_failed_tcp_and_udp_never_reach_website_or_download_stages(self):
        nodes = [{'name': 'n-a', 'type': 'ss', 'server': '8.8.8.8', 'port': 443},
                 {'name': 'n-b', 'type': 'hysteria2', 'server': '8.8.8.8', 'port': 443}]
        def forbidden(port): raise AssertionError('late stage should not run')
        with patch.object(a.s, 'Core'), patch.object(a.s, 'make_listeners', return_value=([], {'n-a': 1, 'n-b': 2})):
            rows, count = a.probe_pipeline(nodes, 'unused', Path('.'),
                precheck=lambda port: {'status': 'passed'}, probe=lambda key, pace: {'status': 'failed'},
                site_check=forbidden, download=forbidden)
        self.assertEqual(count, 1)
        self.assertEqual([r['entry']['status'] for r in rows], ['failed', 'unknown'])

    def test_intermittent_page_and_challenge_never_mark_stable(self):
        rounds = [{label: {'status': 'passed', 'elapsed_ms': 20} for label in a.SITES} for _ in range(3)]
        rounds[1]['Google']['status'] = 'failed'
        rounds[2]['ChatGPT']['status'] = 'needs_review'
        result = a.summarize_rounds(rounds)
        self.assertEqual(result['Google']['status'], 'unstable')
        self.assertEqual(result['Google']['passed_count'], 2)
        self.assertEqual(result['ChatGPT']['status'], 'needs_review')
        self.assertEqual(result['YouTube']['status'], 'passed')

    def test_light_probes_keep_three_rounds_and_rank_by_successful_latency(self):
        rounds = [{label: {'status': 'passed', 'elapsed_ms': delay} for label in a.SITES} for delay in (30, 10, 20)]
        rounds[1]['ClaudeTrace'] = {'status': 'failed', 'elapsed_ms': 8000}
        result = a.summarize_rounds(rounds)
        self.assertEqual(result['Google204']['median_elapsed_ms'], 20)
        self.assertEqual(result['Google204']['max_elapsed_ms'], 30)
        self.assertEqual(result['ClaudeTrace']['status'], 'unstable')
        self.assertEqual(result['ClaudeTrace']['median_elapsed_ms'], 25)
        self.assertEqual(result['ClaudeTrace']['max_elapsed_ms'], 30)
        self.assertEqual(result['ClaudeTrace']['passed_count'], 2)
        record = {'id': 'n-a', 'entry': {'status': 'passed', 'latency_ms': 10}, 'websites': result}
        self.assertEqual(a.website_count(record), len(a.PAGE_SITES))
        self.assertEqual(a.connectivity_count(record), 2)
        faster = copy.deepcopy(record); faster['id'] = 'n-b'; faster['entry']['latency_ms'] = 100
        record['precheck'] = {'median_elapsed_ms': 20}
        faster['precheck'] = {'median_elapsed_ms': 1}
        self.assertLess(a.rank_key(faster), a.rank_key(record))
        # A trace success cannot turn a challenged ChatGPT page into a working page.
        faster['websites']['ChatGPT']['status'] = 'needs_review'
        self.assertEqual(a.website_count(faster), len(a.PAGE_SITES) - 1)

    def test_all_categories_remain_importable_for_local_comparison(self):
        records = [{'id': 'n-' + str(i)*12, 'entry': {'status': status}, 'websites': None, 'exit': None}
                   for i, status in [(1, 'passed'), (2, 'failed'), (3, 'unknown')]]
        records[0]['websites'] = {k: {'status': 'passed', 'passed_count': 3} for k in a.SITES}
        records[0]['exit'] = {'country_code': 'HK', 'exit_ip': '8.8.8.8'}
        records[0]['ip_type'] = {'status': 'unknown', 'hosting': None}
        mapping = {r['id']: {'name': r['id'], 'type': 'http', 'server': '8.8.8.8', 'port': 80} for r in records}
        base = {'dns': {}, 'rules': ['MATCH,🚀 全局选择'], 'rule-providers': {}}
        original = copy.deepcopy(base)
        config = a.render_comparison(base, records, mapping)
        self.assertEqual(len(config['proxies']), 3)
        groups = {g['name']: g['proxies'] for g in config['proxy-groups']}
        for group in ('📶 TCP通', '⛔ TCP不通', '🔎 TCP未验证'):
            self.assertEqual(len(groups[group]), 1)
            self.assertNotEqual(groups[group], ['REJECT'])
        self.assertEqual(groups['🏠 非机房 IP'], ['REJECT'])
        self.assertEqual(groups['⭐ 综合优选'], [records[0]['name']])
        self.assertEqual(len(groups), 8)
        self.assertEqual(groups['🎯 全部节点'], [n['name'] for n in config['proxies']])
        self.assertEqual(base, original)
        valid = {p['name'] for p in config['proxies']} | set(groups) | {'DIRECT', 'REJECT'}
        self.assertTrue(all(name in valid for proxies in groups.values() for name in proxies))
        self.assertTrue(all('MiB' not in n['name'] for n in config['proxies']))

    def test_regional_picker_keeps_per_country_quota_without_extra_groups(self):
        records = []
        for country in ('JP', 'US'):
            for index in range(35):
                records.append({'id': f'n-{country}-{index}', 'entry': {'status': 'passed'},
                    'websites': {label: {'status': 'passed'} for label in a.PAGE_SITES},
                    'precheck': {'status': 'passed', 'median_elapsed_ms': index + 1},
                    'exit': {'country_code': country, 'exit_ip': f'8.8.{country == "JP"}.{index}'},
                    'download': {'status': 'passed', 'speed_mib_s': 1}})
        mapping = {r['id']: {'name': r['id'], 'type': 'http', 'server': '8.8.8.8', 'port': 80} for r in records}
        config = a.render_comparison({'rules': ['MATCH,🚀 全局选择']}, records, mapping)
        groups = {g['name']: g['proxies'] for g in config['proxy-groups']}
        regional = groups['🌍 按地区选择']
        self.assertEqual(len(groups), 8)
        self.assertEqual(sum(name.startswith('日本 |') for name in regional), 30)
        self.assertEqual(sum(name.startswith('美国 |') for name in regional), 30)
        self.assertNotIn('日本', groups)
        self.assertNotIn('美国', groups)
        self.assertEqual(len(groups['🎯 全部节点']), 70)
        for country in ('日本', '美国'):
            included = [name for name in regional if name.startswith(country + ' |')]
            self.assertTrue(all('204 35ms' not in name for name in included))


if __name__ == '__main__':
    unittest.main()
