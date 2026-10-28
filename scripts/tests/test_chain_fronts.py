"""Tests for optional chained-subscription generation.

--- @ty.aicoding@1793178323445 ---
"""

import copy
import unittest
from unittest import mock

import chain_fronts as cf


def record(index, entry='passed', tls='passed', sites=1):
    return {
        'id': f'n{index}',
        'entry': {'status': entry, 'latency_ms': 40 + index},
        'website_tls': {'status': tls},
        'websites': {'sites': sites},
    }


def node(index, server=None, port=443, protocol='vless'):
    return {
        'name': f'n{index}',
        'server': server or f'10.0.0.{index + 1}',
        'port': port,
        'type': protocol,
    }


def base_config():
    return {
        'proxies': [
            {'name': '美国01|100ms|50Mbps|住宅|纯净度99%', 'server': '2.2.2.2', 'port': 80, 'type': 'http'},
            {'name': '日本01|90ms|20Mbps|住宅|纯净度99%', 'server': '3.3.3.3', 'port': 80, 'type': 'http'},
        ],
        'proxy-groups': [{'name': '🚀 全局选择', 'type': 'select', 'proxies': ['美国01|100ms|50Mbps|住宅|纯净度99%']}],
        'rules': ['MATCH,🚀 全局选择'],
    }


class SelectCandidatesTest(unittest.TestCase):
    def setUp(self):
        self.records = [record(i) for i in range(6)]
        self.mapping = {f'n{i}': node(i) for i in range(6)}
        self.countries = {f'10.0.0.{i + 1}': 'JP' for i in range(6)}
        patcher = mock.patch.object(cf, 'website_sites_passed', side_effect=lambda r, m: r['websites']['sites'] >= m)
        self.sites = patcher.start()
        self.addCleanup(patcher.stop)

    def test_filters_entry_tls_and_sites(self):
        self.records[0]['entry']['status'] = 'failed'
        self.records[1]['website_tls']['status'] = 'failed'
        self.records[2]['websites']['sites'] = 0
        got = cf.select_candidates(self.records, self.mapping, self.countries, min_sites=1)
        self.assertEqual([item['record']['id'] for item in got], ['n3', 'n4', 'n5'])

    def test_rejects_non_front_region(self):
        self.countries = {f'10.0.0.{i + 1}': 'US' for i in range(6)}
        self.assertEqual(cf.select_candidates(self.records, self.mapping, self.countries), [])

    def test_rejects_udp_only_transport(self):
        self.mapping['n0'] = node(0, protocol='hysteria2')
        got = cf.select_candidates(self.records, self.mapping, self.countries)
        self.assertNotIn('n0', [item['record']['id'] for item in got])

    def test_dedupes_by_endpoint(self):
        self.mapping['n1'] = node(1, server='10.0.0.1', port=443)
        got = cf.select_candidates(self.records, self.mapping, self.countries)
        keys = [cf.endpoint_key(item['node']) for item in got]
        self.assertEqual(len(keys), len(set(keys)))

    def test_region_limit_and_order(self):
        got = cf.select_candidates(self.records, self.mapping, self.countries, limit_per_region=2)
        self.assertEqual(len(got), 2)


class SummariseTest(unittest.TestCase):
    def test_keeps_front_with_one_good_round(self):
        fronts = [{'record': record(0), 'node': node(0), 'region': 'JP'},
                  {'record': record(1), 'node': node(1), 'region': 'JP'}]
        results = {
            'P000-00': [{'ok': False, 'latency_ms': None}, {'ok': True, 'latency_ms': 90}],
            'P000-01': [{'ok': False, 'latency_ms': None}, {'ok': False, 'latency_ms': None}],
        }
        rows = cf.summarise(fronts, 1, results, rounds=2)
        self.assertEqual(rows[0]['best_reachable'], 1)
        self.assertEqual(rows[1]['best_reachable'], 0)


    def test_counts_every_landing_per_round(self):
        fronts = [{'record': record(0), 'node': node(0), 'region': 'JP'}]
        results = {
            'P000-00': [{'ok': True, 'latency_ms': 80}, {'ok': True, 'latency_ms': 80}],
            'P001-00': [{'ok': True, 'latency_ms': 90}, {'ok': False, 'latency_ms': None}],
            'P002-00': [{'ok': False, 'latency_ms': None}, {'ok': True, 'latency_ms': 100}],
        }
        rows = cf.summarise(fronts, 3, results, rounds=2)
        self.assertEqual(rows[0]['reachable_by_round'], [2, 2])
        self.assertEqual(rows[0]['best_reachable'], 2)

    def test_sorts_by_best_reachable(self):
        fronts = [{'record': record(0), 'node': node(0), 'region': 'JP'},
                  {'record': record(1), 'node': node(1), 'region': 'JP'}]
        results = {
            'P000-00': [{'ok': True, 'latency_ms': 80}, {'ok': True, 'latency_ms': 80}],
            'P001-00': [{'ok': True, 'latency_ms': 80}, {'ok': True, 'latency_ms': 80}],
            'P000-01': [{'ok': True, 'latency_ms': 120}, {'ok': False, 'latency_ms': None}],
            'P001-01': [{'ok': True, 'latency_ms': 120}, {'ok': False, 'latency_ms': None}],
        }
        rows = cf.summarise(fronts, 2, results, rounds=2)
        self.assertEqual(rows[0]['front']['record']['id'], 'n0')


class RenderTest(unittest.TestCase):
    def test_render_adds_fronts_group_and_dialer(self):
        base = base_config()
        original = copy.deepcopy(base)
        rows = [{'front': {'record': record(0), 'node': node(0), 'region': 'JP'},
                 'reachable_by_round': [3, 4], 'best_reachable': 4, 'median_latency_ms': 88}]
        config = cf.render(base, rows)
        self.assertEqual(base, original)
        self.assertTrue(config['proxies'][0]['name'].startswith(cf.FRONT_PREFIX))
        self.assertEqual(config['proxy-groups'][0]['name'], cf.FRONT_GROUP)
        for item in config['proxies'][1:]:
            self.assertEqual(item['dialer-proxy'], cf.FRONT_GROUP)
        self.assertNotIn('dialer-proxy', config['proxies'][0])


class BuildTest(unittest.TestCase):
    def setUp(self):
        self.records = [record(i) for i in range(4)]
        self.mapping = {f'n{i}': node(i) for i in range(4)}
        patcher = mock.patch.object(cf, 'website_sites_passed', return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_disabled_when_pool_too_small(self):
        _, summary = cf.build(base_config(), self.records[:2], self.mapping,
                              geo_lookup=lambda hosts: {f'10.0.0.{i + 1}': 'JP' for i in range(2)})
        self.assertFalse(summary['enabled'])
        self.assertEqual(summary['reason'], 'front_pool_too_small')

    def test_disabled_without_us_landing(self):
        base = base_config()
        base['proxies'] = [base['proxies'][1]]
        _, summary = cf.build(base, self.records, self.mapping,
                              geo_lookup=lambda hosts: {f'10.0.0.{i + 1}': 'JP' for i in range(4)})
        self.assertFalse(summary['enabled'])
        self.assertEqual(summary['reason'], 'no_us_landing')

    def test_eliminates_front_dead_in_both_rounds(self):
        def verifier(fronts, landings, binary, root, **kwargs):
            results = {}
            for index, _front in enumerate(fronts):
                results[f'P000-{index:02d}'] = [{'ok': index != 3, 'latency_ms': 100},
                                                {'ok': index != 3, 'latency_ms': 100}]
            return results

        config, summary = cf.build(
            base_config(), self.records, self.mapping, binary='mihomo', root='/tmp',
            geo_lookup=lambda hosts: {f'10.0.0.{i + 1}': 'JP' for i in range(4)},
            verifier=verifier)
        self.assertTrue(summary['enabled'])
        self.assertEqual(summary['survivors'], 3)
        self.assertTrue(config['proxies'][0]['name'].startswith(cf.FRONT_PREFIX))

    def test_all_dead_disables_chain(self):
        def verifier(fronts, landings, binary, root, **kwargs):
            return {f'P000-{index:02d}': [{'ok': False, 'latency_ms': None},
                                          {'ok': False, 'latency_ms': None}]
                    for index in range(len(fronts))}

        config, summary = cf.build(
            base_config(), self.records, self.mapping, binary='mihomo', root='/tmp',
            geo_lookup=lambda hosts: {f'10.0.0.{i + 1}': 'JP' for i in range(4)},
            verifier=verifier)
        self.assertIsNone(config)
        self.assertFalse(summary['enabled'])
        self.assertEqual(summary['reason'], 'survivors_too_few')


if __name__ == '__main__':
    unittest.main()
