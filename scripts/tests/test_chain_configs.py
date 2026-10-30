"""Tests for the three chain products.

--- @ty.aicoding@1793205643486 ---
"""

import copy
import unittest
from unittest import mock

import chain_configs as cc


def record(index, entry='passed', precheck='passed', median=120, server_suffix=None,
           exit_country='JP'):
    return {
        'id': f'n{index}',
        'precheck': {'status': precheck, 'median_elapsed_ms': median},
        'entry': {'status': entry, 'latency_ms': 40 + index},
        'website_tls': {'status': 'passed'},
        'download': {'status': 'passed', 'speed_mib_s': 10 + index},
        'quick3_download': {'status': 'passed'},
        'high_speed_download': {'status': 'passed', 'speed_mib_s': 9 + index},
        'upload_precheck': {'status': 'passed'},
        'front_probe': {'cn': {'status': 'passed'}, 'intl': {'status': 'passed'},
                        'tls': {'status': 'passed'},
                        'down10': {'status': 'passed'}},
        'exit': {'country_code': exit_country},
        'app_tls': {'status': 'passed'},
        'stability': {'success_rate': 0.99},
    }


def node(index, server=None, port=443, protocol='vless'):
    return {'name': f'n{index}', 'server': server or f'10.0.0.{index + 1}',
            'port': port, 'type': protocol}


def base_config():
    return {
        'mixed-port': 7890, 'mode': 'rule', 'log-level': 'info',
        'ipv6': True,
        'dns': {'enable': True, 'ipv6': True, 'nameserver': ['223.5.5.5']},
        'rules': ['DOMAIN-SUFFIX,example.com,🚀 全局选择', 'MATCH,🚀 全局选择'],
        'rule-providers': {'proxy': {'type': 'http', 'behavior': 'domain',
                                     'url': 'https://example.com/proxy.yaml',
                                     'path': './rules/proxy.yaml'}},
        'sniffer': {'enable': True},
    }



def fronts_fixture():
    return [{'record': record(0), 'node': node(0, server='1.1.1.1')}]


def landings_fixture():
    return [
        {'name': '美国01|100ms|50Mbps|机房|纯净度未知', 'server': '2.2.2.2', 'port': 80, 'type': 'http'},
        {'name': '美国02|120ms|60Mbps|住宅|纯净度未知', 'server': '2.2.2.3', 'port': 80, 'type': 'http'},
        {'name': '德国01|200ms|20Mbps|机房|纯净度未知', 'server': '3.3.3.3', 'port': 80, 'type': 'http'},
    ]

def ext_fixture():
    return [{'name': '🛫 订阅 美国01', 'server': '9.9.9.9', 'port': 443, 'type': 'vless'}]

class SelectionTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(cc, 'is_cloudflare', return_value=False)
        patcher.start(); self.addCleanup(patcher.stop)
        for target, attr, value in (
            ('availability.required_websites_passed', None, True),
            ('app_tls.passed', None, True),
            ('stability.passed', None, True),
            ('availability.tcp_supported', None, True),
            ('high_speed.passed', None, True),
        ):
            module, name = target.rsplit('.', 1)
            p = mock.patch(f'{module}.{name}', return_value=value)
            p.start(); self.addCleanup(p.stop)

    def test_landing_does_not_require_domestic_tcp(self):
        records = [record(0, entry='failed')]
        mapping = {'n0': node(0)}
        landings = cc.select_landings(records, mapping)
        self.assertEqual([n['server'] for n in landings], [mapping['n0']['server']])

    def test_landing_rejects_slow_204(self):
        records = [record(0, median=2500)]
        self.assertEqual(cc.select_landings(records, {'n0': node(0)}), [])

    def test_landing_rejects_failed_precheck(self):
        records = [record(0, precheck='failed')]
        self.assertEqual(cc.select_landings(records, {'n0': node(0)}), [])

    def test_landing_rejects_udp_protocol(self):
        records = [record(0)]
        with mock.patch('availability.tcp_supported',
                        side_effect=lambda n: n['type'] not in {'hysteria2', 'tuic'}):
            self.assertEqual(cc.select_landings(records, {'n0': node(0, protocol='hysteria2')}), [])
            self.assertEqual(len(cc.select_landings(records, {'n0': node(0, protocol='vless')})), 1)

    def test_landing_requires_100mb(self):
        records = [record(0)]
        with mock.patch('high_speed.passed', return_value=False):
            self.assertEqual(cc.select_landings(records, {'n0': node(0)}), [])

    def test_landing_names_use_exit_country_and_speed_order(self):
        records = [record(0, exit_country='US'), record(1, exit_country='US'),
                   record(2, exit_country='JP')]
        mapping = {'n0': node(0), 'n1': node(1), 'n2': node(2)}
        names = [n['name'] for n in cc.select_landings(records, mapping)]
        self.assertEqual(names, ['日本01|120ms|92Mbps|未知|纯净度未知',
                                 '美国01|120ms|84Mbps|未知|纯净度未知',
                                 '美国02|120ms|75Mbps|未知|纯净度未知'])

    def test_landing_dedupes_endpoint(self):
        records = [record(0), record(1)]
        mapping = {'n0': node(0, server='1.2.3.4'), 'n1': node(1, server='1.2.3.4')}
        self.assertEqual(len(cc.select_landings(records, mapping)), 1)

    def test_front_keeps_every_region_after_tcp(self):
        records = [record(0), record(1)]
        mapping = {'n0': node(0, server='1.1.1.1'), 'n1': node(1, server='2.2.2.2')}
        fronts = cc.select_fronts(records, mapping)
        self.assertEqual(sorted(f['node']['server'] for f in fronts),
                         ['1.1.1.1', '2.2.2.2'])

    def test_front_sorted_by_download_speed(self):
        records = [record(0), record(1)]
        mapping = {'n0': node(0), 'n1': node(1)}
        fronts = cc.select_fronts(records, mapping)
        self.assertEqual([f['node']['name'] for f in fronts], ['n1', 'n0'])

    def test_front_rejects_failed_entry(self):
        records = [record(0, entry='failed')]
        self.assertEqual(cc.select_fronts(records, {'n0': node(0)}), [])


class RenderTest(unittest.TestCase):
    def test_chain_inlines_nodes_and_copies_rules(self):
        base = base_config()
        original = copy.deepcopy(base)
        config = cc.render_chain(base, fronts_fixture(), landings_fixture())
        self.assertNotIn('proxy-providers', config)
        self.assertEqual(len(config['proxies']), 4)  # 1 个前置 + 3 个落地
        self.assertTrue(all(node.get('dialer-proxy') in (None, cc.FRONT_GROUP)
                            for node in config['proxies']))
        self.assertEqual(config['proxies'][1]['dialer-proxy'], cc.FRONT_GROUP)
        self.assertEqual(config['rules'], base['rules'])
        self.assertFalse(config['ipv6'])
        self.assertFalse(config['dns']['ipv6'])
        self.assertEqual(base, original)

    def test_chain_groups_cover_regions_without_provider_filters(self):
        config = cc.render_chain(base_config(), fronts_fixture(), landings_fixture())
        names = {g['name']: g for g in config['proxy-groups']}
        self.assertIn(cc.FRONT_GROUP, names)
        self.assertEqual(names[cc.FRONT_GROUP]['proxies'][0], cc.AUTO_GROUP)
        self.assertEqual(len(names[cc.AUTO_GROUP]['proxies']), 1)
        self.assertEqual(names[cc.US_GROUP]['proxies'],
                         ['美国01|100ms|50Mbps|机房|纯净度未知', '美国02|120ms|60Mbps|住宅|纯净度未知'])
        self.assertEqual(names[cc.US_HOSTING_GROUP]['proxies'], ['美国01|100ms|50Mbps|机房|纯净度未知'])
        self.assertEqual(names[cc.US_RESIDENTIAL_GROUP]['proxies'], ['美国02|120ms|60Mbps|住宅|纯净度未知'])
        self.assertNotIn('use', names[cc.FRONT_GROUP])

    def test_external_subscription_nodes_are_inlined_into_the_front_groups(self):
        config = cc.render_chain(base_config(), fronts_fixture(), landings_fixture(), ext_fixture())
        names = {g['name']: g for g in config['proxy-groups']}
        self.assertNotIn('proxy-providers', config)
        self.assertEqual([p['name'] for p in config['proxies']][1], '🛫 订阅 美国01')
        self.assertIn('🛫 订阅 美国01', names[cc.FRONT_GROUP]['proxies'])
        self.assertIn('🛫 订阅 美国01', names[cc.AUTO_GROUP]['proxies'])
        self.assertNotIn('🛫 订阅 美国01', names[cc.US_GROUP]['proxies'])
        self.assertIn('德国01|200ms|20Mbps|机房|纯净度未知', names['🇪🇺 欧洲']['proxies'])
        self.assertNotIn('use', names[cc.US_GROUP])

    def test_front_config_single_flat_group(self):
        base = base_config()
        fronts = [
            {'record': record(0), 'node': node(0, server='1.1.1.1')},
            {'record': record(1), 'node': node(1, server='2.2.2.2')},
        ]
        config = cc.render_front(base, fronts)
        self.assertEqual(len(config['proxies']), 2)
        self.assertTrue(all(p['name'].startswith(cc.FRONT_PREFIX) for p in config['proxies']))
        self.assertEqual(config['rules'], base['rules'])
        self.assertFalse(config['ipv6'])
        groups = {g['name']: g for g in config['proxy-groups']}
        self.assertEqual(set(groups), {cc.GLOBAL_GROUP, cc.FRONT_TEST_GROUP})
        self.assertEqual(groups[cc.FRONT_TEST_GROUP]['type'], 'url-test')
        self.assertEqual(len(groups[cc.FRONT_TEST_GROUP]['proxies']), 2)
        self.assertIn(cc.FRONT_TEST_GROUP, groups[cc.GLOBAL_GROUP]['proxies'])
        self.assertNotIn('proxy-providers', config)

    def test_landing_config_groups_by_region(self):
        base = base_config()
        landings = [
            {'name': '美国01|100ms|50Mbps|机房|纯净度99%', 'server': '1.1.1.1', 'port': 80, 'type': 'http'},
            {'name': '美国02|120ms|60Mbps|住宅|纯净度98%', 'server': '1.1.1.2', 'port': 80, 'type': 'http'},
            {'name': '美国03|130ms|70Mbps|未知|纯净度未知', 'server': '1.1.1.3', 'port': 80, 'type': 'http'},
            {'name': '德国01|200ms|20Mbps|机房|纯净度99%', 'server': '2.2.2.2', 'port': 80, 'type': 'http'},
        ]
        config = cc.render_landing(base, landings)
        groups = {g['name']: g for g in config['proxy-groups']}
        self.assertIn(cc.US_GROUP, groups)
        self.assertIn('🇪🇺 欧洲', groups)
        self.assertEqual(groups[cc.US_GROUP]['proxies'],
                         ['美国01|100ms|50Mbps|机房|纯净度99%',
                          '美国02|120ms|60Mbps|住宅|纯净度98%',
                          '美国03|130ms|70Mbps|未知|纯净度未知'])
        self.assertEqual(groups[cc.US_HOSTING_GROUP]['proxies'], ['美国01|100ms|50Mbps|机房|纯净度99%'])
        self.assertEqual(groups[cc.US_RESIDENTIAL_GROUP]['proxies'], ['美国02|120ms|60Mbps|住宅|纯净度98%'])
        self.assertEqual(groups[cc.GLOBAL_GROUP]['proxies'][:3],
                         [cc.US_GROUP, cc.US_HOSTING_GROUP, cc.US_RESIDENTIAL_GROUP])


class BuildTest(unittest.TestCase):
    def setUp(self):
        for target in ('availability.required_websites_passed', 'app_tls.passed',
                       'stability.passed', 'availability.tcp_supported', 'high_speed.passed'):
            module, name = target.rsplit('.', 1)
            p = mock.patch(f'{module}.{name}', return_value=True)
            p.start(); self.addCleanup(p.stop)
        p = mock.patch.object(cc, 'is_cloudflare', return_value=False)
        p.start(); self.addCleanup(p.stop)

    def test_build_returns_three_configs(self):
        records = [record(0), record(1)]
        mapping = {'n0': node(0, server='1.1.1.1'), 'n1': node(1, server='2.2.2.2')}
        front, landing, chain, summary = cc.build(base_config(), records, mapping)
        self.assertIsNotNone(front)
        self.assertIsNotNone(landing)
        self.assertIsNotNone(chain)
        self.assertEqual(summary['fronts'], 2)
        self.assertEqual(summary['landings'], 2)
        self.assertTrue(summary['chain_enabled'])


if __name__ == '__main__':
    unittest.main()
