import copy
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

    def test_merge_rejects_missing_duplicate_wrong_batch_and_incomplete_rounds(self):
        nodes = [{'name': f'n-{i}', 'type': 'ss', 'server': f'8.8.8.{i}', 'port': 443} for i in range(20)]
        bundle = {'id': 'batch', 'nodes': nodes}
        parts = [{'bundle_id': 'batch', 'index': i, 'count': 4, 'endpoint_count': len(a.shard_nodes(nodes, i, 4)),
                  'records': [{'id': n['name'], 'entry': {'status': 'failed'}, 'websites': None}
                              for n in a.shard_nodes(nodes, i, 4)]} for i in range(4)]
        records, endpoints = a.merge_shards(bundle, parts, 4)
        self.assertEqual([r['id'] for r in records], [n['name'] for n in nodes])
        self.assertEqual(endpoints, 20)
        broken = [parts[:-1]]
        wrong = copy.deepcopy(parts); wrong[0]['bundle_id'] = 'old'; broken.append(wrong)
        wrong = copy.deepcopy(parts); wrong[0]['records'].append(wrong[0]['records'][0]); broken.append(wrong)
        wrong = copy.deepcopy(parts); wrong[0]['records'][0]['entry']['status'] = 'passed'; broken.append(wrong)
        for case in broken:
            with self.assertRaises(ValueError): a.merge_shards(bundle, case, 4)

    def test_websites_start_before_last_tcp_probe_finishes(self):
        started = threading.Event()
        overlap = []
        nodes = [{'name': 'n-a', 'type': 'ss', 'server': '8.8.8.8', 'port': 443},
                 {'name': 'n-b', 'type': 'ss', 'server': '1.1.1.1', 'port': 443}]
        def probe(key, pace):
            if key[0] == '1.1.1.1':
                overlap.append(started.wait(timeout=1))
                return {'status': 'failed'}
            return {'status': 'passed'}
        def websites(port):
            started.set()
            return {label: {'status': 'passed', 'elapsed_ms': 1} for label in a.SITES}
        with patch.object(a.s, 'Core'), patch.object(a.s, 'make_listeners', return_value=([], {'n-a': 1, 'n-b': 2})), \
             patch.object(a.s, 'query_exit', return_value={'exit_ip': '8.8.8.8', 'country_code': 'US'}), \
             patch.object(a.time, 'sleep'):
            records, endpoints = a.probe_pipeline(nodes, 'unused', Path('.'), probe=probe, site_check=websites)
        self.assertEqual(overlap, [True], '网站等待了所有 TCP 探测结束')
        self.assertEqual(endpoints, 2)
        self.assertEqual(records[0]['websites']['Google']['passed_count'], 3)
        self.assertIsNone(records[1]['websites'])

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

    def test_failed_and_unknown_nodes_never_reach_websites_or_downloads(self):
        with patch.object(a.s, 'download_file', side_effect=AssertionError('download forbidden')), \
             patch.object(a.s, 'measure_file', side_effect=AssertionError('download forbidden')), \
             patch.object(a.s, 'query_exit', return_value={'exit_ip': '8.8.8.8', 'country_code': 'US'}), \
             patch.object(a.time, 'sleep'):
            calls = []
            def websites(port):
                calls.append(port)
                return {label: {'status': 'passed', 'elapsed_ms': 20} for label in a.SITES}
            for status in ('failed', 'unknown'):
                r = a.check_repeated(1234, {'entry': {'status': status}}, site_check=websites)
                self.assertNotIn('websites', r)
            r = a.check_repeated(1234, {'id': 'n-a', 'entry': {'status': 'passed'}}, site_check=websites)
            self.assertEqual(calls, [1234]*3)
            self.assertTrue(all(v['round_count'] == v['passed_count'] == 3 for v in r['websites'].values()))

    def test_intermittent_page_and_challenge_never_mark_stable(self):
        rounds = [{label: {'status': 'passed', 'elapsed_ms': 20} for label in a.SITES} for _ in range(3)]
        rounds[1]['Google']['status'] = 'failed'
        rounds[2]['ChatGPT']['status'] = 'needs_review'
        result = a.summarize_rounds(rounds)
        self.assertEqual(result['Google']['status'], 'unstable')
        self.assertEqual(result['Google']['passed_count'], 2)
        self.assertEqual(result['ChatGPT']['status'], 'needs_review')
        self.assertEqual(result['YouTube']['status'], 'passed')

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
        self.assertEqual(groups['✅ 三站稳定'], [records[0]['name']])
        self.assertEqual(base, original)
        valid = {p['name'] for p in config['proxies']} | set(groups) | {'DIRECT', 'REJECT'}
        self.assertTrue(all(name in valid for proxies in groups.values() for name in proxies))
        self.assertTrue(all('MiB' not in n['name'] for n in config['proxies']))


if __name__ == '__main__':
    unittest.main()
