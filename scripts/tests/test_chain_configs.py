"""Tests for the three chain products.

--- @ty.aicoding@1793205643486 ---
"""

import copy
import unittest
from pathlib import Path
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
    return [{'name': 'US 官方优选 187ms', 'server': '9.9.9.9', 'port': 443, 'type': 'vless'}]

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

    def test_external_subscription_is_fetched_with_a_clash_user_agent(self):
        payload = 'proxies:\n  - {name: US01, type: vless, server: 9.9.9.9, port: 443}\n'
        with mock.patch.dict('os.environ', {'CHAIN_EXTERNAL_SUB': 'on'}), \
                mock.patch('select_nodes.session') as session:
            client = session.return_value.__enter__.return_value
            client.get.return_value.text = payload
            nodes = cc.external_fronts('https://example.invalid/sub')
        self.assertEqual([n['name'] for n in nodes], ['US01'])
        self.assertEqual(client.get.call_args.kwargs['headers']['User-Agent'], 'clash-verge/v1.0')

    def test_previous_chain_nodes_are_reused_when_the_subscription_fails(self):
        import json, tempfile
        config = cc.render_chain(base_config(), fronts_fixture(), landings_fixture(), ext_fixture())
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / '链式配置.yaml'
            path.write_text(json.dumps(config, ensure_ascii=False), encoding='utf-8')
            nodes = cc.previous_external_fronts(str(path))
        self.assertEqual([n['name'] for n in nodes], ['US 官方优选 187ms'])

    def test_manual_groups_come_before_automatic_ones(self):
        config = cc.render_chain(base_config(), fronts_fixture(), landings_fixture(), ext_fixture())
        order = [g['name'] for g in config['proxy-groups']]
        self.assertEqual(order[:3], [cc.FRONT_GROUP, cc.EXT_GROUP, cc.GLOBAL_GROUP])
        self.assertEqual(order[3:5], [cc.AUTO_GROUP, cc.EXT_AUTO_GROUP])
        self.assertEqual(order[5:], [cc.US_GROUP, cc.US_HOSTING_GROUP, cc.US_RESIDENTIAL_GROUP,
                                     '🇪🇺 欧洲', '🌐 全部节点'])

    def test_external_subscription_nodes_get_their_own_group(self):
        config = cc.render_chain(base_config(), fronts_fixture(), landings_fixture(), ext_fixture())
        names = {g['name']: g for g in config['proxy-groups']}
        self.assertNotIn('proxy-providers', config)
        # 名字保留订阅里的原样，不加前缀。
        self.assertEqual([p['name'] for p in config['proxies']][1], 'US 官方优选 187ms')
        # 前置组只有两个选项：自动前置、yieti 分组。
        self.assertEqual(names[cc.FRONT_GROUP]['proxies'], [cc.AUTO_GROUP, cc.EXT_GROUP])
        # yieti：手动组里第一项是自动测速组，其余节点仍可强制选中。
        self.assertEqual(names[cc.EXT_GROUP]['type'], 'select')
        self.assertEqual(names[cc.EXT_GROUP]['proxies'], [cc.EXT_AUTO_GROUP, 'US 官方优选 187ms'])
        self.assertEqual(names[cc.EXT_AUTO_GROUP]['type'], 'url-test')
        self.assertEqual(names[cc.EXT_GROUP]['default-selected'], cc.EXT_AUTO_GROUP)
        self.assertEqual(names[cc.EXT_AUTO_GROUP]['proxies'], ['US 官方优选 187ms'])
        self.assertTrue(names[cc.EXT_AUTO_GROUP]['lazy'])
        self.assertNotIn('US 官方优选 187ms', names[cc.AUTO_GROUP]['proxies'])
        self.assertNotIn('US 官方优选 187ms', names[cc.US_GROUP]['proxies'])

    def test_domain_fronted_nodes_are_preferred_over_bare_ips(self):
        nodes = [{'name': 'US ip 100ms', 'server': '1.2.3.4', 'port': 443},
                 {'name': 'US 域名 300ms', 'server': 'cf.example.com', 'port': 443},
                 {'name': 'HK 域名 400ms', 'server': 'youxuan.cf.090227.xyz', 'port': 443},
                 {'name': 'HK ip 200ms', 'server': '5.6.7.8', 'port': 443}]
        latencies = {node['name']: float(node['name'].split()[-1].rstrip('ms')) for node in nodes}
        picked = [node['name'] for node in cc.pick_ext_auto(nodes, latencies, limit=3)]
        self.assertEqual(picked[:2], ['US 域名 300ms', 'HK 域名 400ms'])
        self.assertEqual(picked[2], 'US ip 100ms')
        self.assertTrue(cc.is_domain_server({'server': 'a.example.com'}))
        self.assertFalse(cc.is_domain_server({'server': '1.2.3.4'}))

    def test_auto_picks_by_measured_latency_and_spreads_across_regions(self):
        nodes = ([{'name': f'HK 官方优选 {index}'} for index in range(5)]
                 + [{'name': f'US 官方优选 {index}'} for index in range(5)]
                 + [{'name': f'CF优选 {index}'} for index in range(5)])
        latencies = {node['name']: float(index) for index, node in enumerate(nodes)}
        picked = [node['name'] for node in cc.pick_ext_auto(nodes, latencies)]
        # 每个地区最多 3 个，轮着补齐。
        self.assertEqual(len(picked), 9)
        self.assertEqual(sum('HK' in name for name in picked), 3)
        self.assertEqual(sum('US' in name for name in picked), 3)
        self.assertEqual(sum('CF' in name for name in picked), 3)

    def test_auto_skips_nodes_that_failed_the_probe(self):
        nodes = [{'name': 'HK 1'}, {'name': 'HK 2'}, {'name': 'US 1'}]
        picked = [node['name'] for node in cc.pick_ext_auto(nodes, {'US 1': 80.0})]
        self.assertEqual(picked[0], 'US 1')

    def test_region_comes_from_the_name(self):
        self.assertEqual(cc.ext_region('HK|官方优选|55ms'), 'HK')
        self.assertEqual(cc.ext_region('US 官方优选 187ms'), 'US')
        self.assertEqual(cc.ext_region('CF优选 35.28ms'), 'CF')
        self.assertEqual(cc.ext_region('节点 01'), '其他')

    def test_front_group_has_no_subscription_choice_when_it_is_empty(self):
        config = cc.render_chain(base_config(), fronts_fixture(), landings_fixture(), [])
        names = {g['name']: g for g in config['proxy-groups']}
        self.assertEqual(names[cc.FRONT_GROUP]['proxies'], [cc.AUTO_GROUP])
        self.assertNotIn(cc.EXT_GROUP, names)
        self.assertNotIn(cc.EXT_AUTO_GROUP, names)
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
