#!/usr/bin/env python3
"""Build the three chain products from the same measurement records.

- 前置配置.yaml : fronts only, one flat url-test group
- 后置配置.yaml : landings only, grouped by region, no CN-reachability gate
- 链式配置.yaml : no nodes, two proxy-providers + groups, rules copied from 优选配置

--- @ty.aicoding@1793205643486 ---
"""

import copy
import ipaddress
import math
import socket
from urllib.parse import quote

# 前置不查归属地：国内 TCP 能过、再通过下面几道实测门槛就收，美国之外的都可以。
EU_PREFIXES = ('英国', '德国', '法国', '荷兰', '意大利', '西班牙', '葡萄牙', '波兰', '瑞典',
               '瑞士', '芬兰', '挪威', '丹麦', '爱尔兰', '奥地利', '比利时', '捷克',
               '罗马尼亚', '匈牙利', '希腊', '乌克兰', '俄罗斯', '爱沙尼亚', '拉脱维亚',
               '立陶宛', '冰岛', '卢森堡', '保加利亚', '克罗地亚', '塞尔维亚', '斯洛伐克',
               '斯洛文尼亚')
BASE_KEYS = ('mixed-port', 'allow-lan', 'mode', 'log-level', 'external-controller',
             'dns', 'rules', 'rule-providers', 'find-process-mode', 'ipv6', 'sniffer')
CHECK_URL = 'http://www.gstatic.com/generate_204'
FRONT_PREFIX = '🛫 '
FRONT_TEST_GROUP = '🛫 前置节点'
FRONT_GROUP = '🌉 前置'
AUTO_GROUP = '🔄 自动前置'
GLOBAL_GROUP = '🚀 全局选择'
# 美国拆三组：全部美国节点、其中的机房 IP、其中的住宅 IP；第四段是名字里的机房／住宅标记。
US_GROUP = '🇺🇸 美国节点'
US_HOSTING_GROUP = '🏢 美国机房'
US_RESIDENTIAL_GROUP = '🏠 美国住宅'
US_PREFIX = '美国'
US_HOSTING_MARK = '|机房|'
US_RESIDENTIAL_MARK = '|住宅|'
FRONT_URL = ('https://cdn.jsdelivr.net/gh/hoooou/my_yml@main/'
             + quote('前置配置.yaml'))
LANDING_URL = ('https://cdn.jsdelivr.net/gh/hoooou/my_yml@main/'
               + quote('后置配置.yaml'))
CF_NETWORKS = ('172.64.0.0/13', '104.16.0.0/13', '162.158.0.0/15', '188.114.96.0/20',
               '173.245.48.0/20', '103.21.244.0/22', '131.0.72.0/22', '141.101.64.0/18',
               '108.162.192.0/18', '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17',
               '162.159.0.0/16', '103.22.200.0/22', '103.31.4.0/22', '104.24.0.0/14')


def endpoint(node):
    """Network identity: lowercase server plus port."""
    return str(node.get('server', '')).lower().rstrip('.'), int(node.get('port') or 0)


def is_cloudflare(server, cache=None):
    """Anycast exits follow the ingress colo, so these never belong in a chain."""
    cache = cache if cache is not None else {}
    host = str(server).lower()
    if host in cache:
        return cache[host]
    value = False
    try:
        address = ipaddress.ip_address(socket.gethostbyname(host))
        value = any(address in ipaddress.ip_network(net) for net in CF_NETWORKS)
    except (OSError, ValueError):
        value = False
    cache[host] = value
    return value


def _landing_gates(record, mapping):
    """Strict landing gates; domestic TCP reachability is deliberately absent."""
    from availability import required_websites_passed, tcp_supported
    import app_tls
    import high_speed
    import stability

    # 落地只收 TCP 类型：前置可能是 http/socks5，转发不了 UDP，
    # hysteria2/tuic/wireguard 这类落地会直接断链。
    node = mapping.get(record.get('id'))
    if not node or not tcp_supported(node):
        return False
    if (record.get('precheck') or {}).get('status') != 'passed':
        return False
    median = (record.get('precheck') or {}).get('median_elapsed_ms')
    if not isinstance(median, (int, float)) or median > 2000:
        return False
    if (record.get('website_tls') or {}).get('status') != 'passed':
        return False
    if not required_websites_passed(record):
        return False
    if not app_tls.passed(record.get('app_tls') or {}):
        return False
    if (record.get('download') or {}).get('status') != 'passed':
        return False
    if (record.get('quick3_download') or {}).get('status') != 'passed':
        return False
    # 落地是整条链的出口，100MB 单目标不过就不收。
    if not high_speed.passed(record.get('high_speed_download') or {}):
        return False
    if (record.get('upload_precheck') or {}).get('status') != 'passed':
        return False
    if record.get('stability') is not None and not stability.passed(record.get('stability')):
        return False
    return True


def _front_gates(record, mapping):
    from availability import tcp_supported

    node = mapping.get(record.get('id'))
    if not node or not tcp_supported(node):
        return False
    if (record.get('entry') or {}).get('status') != 'passed':
        return False
    # 前置轨道只看自己的证据：上传、独立 TLS、回国/出国。
    # 不依赖后置轨道的 26 站、应用 TLS、1MB 下载，也不看入口归属地。
    if (record.get('upload_precheck') or {}).get('status') != 'passed':
        return False
    probe = record.get('front_probe') or {}
    if (probe.get('tls') or {}).get('status') != 'passed':
        return False
    if (probe.get('cn') or {}).get('status') != 'passed':
        return False
    if (probe.get('intl') or {}).get('status') != 'passed':
        return False
    return True


def _front_speed(record):
    """排序用已有的下载结果，前置不再单独跑测速。"""
    for key in ('medium_speed_download', 'download'):
        item = record.get(key) or {}
        speed = item.get('speed_mib_s')
        if item.get('status') == 'passed' and isinstance(speed, (int, float)):
            return speed
    return -1


def select_fronts(records, mapping):
    """Every node that passes the front gates; no region filter, fastest first."""
    picked, seen = [], set()
    for record in records:
        if not _front_gates(record, mapping):
            continue
        node = mapping[record['id']]
        key = endpoint(node)
        if key in seen:
            continue
        seen.add(key)
        picked.append({'record': record, 'node': node})
    picked.sort(key=lambda item: (-_front_speed(item['record']),
                                  (item['record'].get('entry') or {}).get('latency_ms') or 1e9))
    return picked


def _landing_speed(record):
    for key in ('high_speed_download', 'medium_speed_download', 'download'):
        item = record.get(key) or {}
        speed = item.get('speed_mib_s')
        if item.get('status') == 'passed' and isinstance(speed, (int, float)):
            return speed
    return None


def _landing_region(record):
    from select_nodes import COUNTRIES

    country = (record.get('exit') or {}).get('country_code')
    return COUNTRIES.get(country, country) if country else '地区未确认'


def _landing_name(record, number):
    from ip_reputation import residence_label

    region = _landing_region(record)
    median = (record.get('precheck') or {}).get('median_elapsed_ms')
    delay = f'{median:.0f}ms' if isinstance(median, (int, float)) else '?ms'
    speed = _landing_speed(record)
    bandwidth = (f'{speed * 1048576 * 8 / 1000000:.0f}Mbps'
                 if isinstance(speed, (int, float)) else '?Mbps')
    housing = {'住宅候选': '住宅', '机房': '机房', '移动网络': '移动网络',
               '非机房': '未知', '住宅未知': '未知'}[residence_label(record)]
    info = record.get('ip_reputation') or {}
    purity = info.get('network_purity_score') if info.get('status') == 'success' else None
    purity_text = (f'纯净度{purity:.1f}%' if isinstance(purity, (int, float)) and math.isfinite(purity)
                   else '纯净度未知')
    return '|'.join([f'{region}{number:02d}', delay, bandwidth, housing, purity_text])


def select_landings(records, mapping):
    picked, seen, cf_cache = [], set(), {}
    for record in records:
        if not _landing_gates(record, mapping):
            continue
        node = mapping[record['id']]
        key = endpoint(node)
        if key in seen or is_cloudflare(node.get('server'), cf_cache):
            continue
        seen.add(key)
        picked.append({'record': record, 'node': copy.deepcopy(node),
                       'speed': _landing_speed(record) or -1})
    picked.sort(key=lambda item: -item['speed'])
    counters, nodes = {}, []
    for item in picked:
        region = _landing_region(item['record'])
        counters[region] = counters.get(region, 0) + 1
        node = item['node']
        node['name'] = _landing_name(item['record'], counters[region])
        nodes.append(node)
    return nodes


def _base(base):
    return {key: copy.deepcopy(base[key]) for key in BASE_KEYS if key in base}


def _group(name, nodes, interval=180):
    return {'name': name, 'type': 'url-test', 'url': CHECK_URL, 'interval': interval,
            'timeout': 5000, 'expected-status': 204, 'tolerance': 50, 'lazy': False,
            'proxies': nodes}


def render_front(base, fronts):
    config = _base(base)
    config['ipv6'] = False
    config.setdefault('dns', {})['ipv6'] = False
    nodes, names = [], []
    for index, item in enumerate(fronts, 1):
        entry = (item['record'].get('entry') or {}).get('latency_ms')
        speed = _front_speed(item['record'])
        if speed < 0:
            speed = None
        bandwidth = f"{speed * 8:.0f}Mbps" if isinstance(speed, (int, float)) else '?Mbps'
        entry_text = f"{int(entry)}ms" if isinstance(entry, (int, float)) else '?ms'
        name = f"{FRONT_PREFIX}{index:02d}|{entry_text}|{bandwidth}"
        node = copy.deepcopy(item['node'])
        node['name'] = name
        nodes.append(node)
        names.append(name)
    config['proxies'] = nodes
    config['proxy-groups'] = [
        {'name': GLOBAL_GROUP, 'type': 'select',
         'proxies': [FRONT_TEST_GROUP, 'DIRECT']},
        _group(FRONT_TEST_GROUP, names),
    ]
    return config


def render_landing(base, landings):
    config = _base(base)
    config['ipv6'] = False
    config.setdefault('dns', {})['ipv6'] = False
    config['proxies'] = [copy.deepcopy(node) for node in landings]
    names = [node['name'] for node in config['proxies']]
    eu = [n for n in names if str(n).startswith(EU_PREFIXES)]
    us = [n for n in names if str(n).startswith(US_PREFIX)]
    groups = [
        _group(US_GROUP, us),
        _group(US_HOSTING_GROUP, [n for n in us if US_HOSTING_MARK in str(n)]),
        _group(US_RESIDENTIAL_GROUP, [n for n in us if US_RESIDENTIAL_MARK in str(n)]),
        _group('🇯🇵 日本', [n for n in names if str(n).startswith('日本')]),
        _group('🇸🇬 新加坡', [n for n in names if str(n).startswith('新加坡')]),
        _group('🇪🇺 欧洲', eu),
        _group('🌐 全部节点', names),
    ]
    groups = [g for g in groups if g['proxies']]
    config['proxy-groups'] = [
        {'name': GLOBAL_GROUP, 'type': 'select',
         'proxies': [g['name'] for g in groups] + ['DIRECT']},
    ] + groups
    return config


def render_chain(base):
    config = _base(base)
    config['ipv6'] = False
    config.setdefault('dns', {})['ipv6'] = False
    config['proxies'] = []
    config['proxy-providers'] = {
        'front': {'type': 'http', 'url': FRONT_URL, 'interval': 3600,
                  'path': './providers/front.yaml', 'proxy': 'DIRECT'},
        'landing': {'type': 'http', 'url': LANDING_URL, 'interval': 3600,
                    'path': './providers/landing.yaml', 'proxy': 'DIRECT',
                    'override': {'dialer-proxy': FRONT_GROUP}},
    }
    region_groups = [
        _group(US_GROUP, []), _group(US_HOSTING_GROUP, []), _group(US_RESIDENTIAL_GROUP, []),
        _group('🇯🇵 日本', []), _group('🇸🇬 新加坡', []),
        _group('🇪🇺 欧洲', []), _group('🌐 全部节点', []),
    ]
    filters = ['^' + US_PREFIX,
               '^' + US_PREFIX + '.*[|]机房[|]',
               '^' + US_PREFIX + '.*[|]住宅[|]',
               '^日本', '^新加坡', '^(' + '|'.join(EU_PREFIXES) + ')']
    for group, pattern in zip(region_groups, filters + ['']):
        group.pop('proxies', None)
        group['use'] = ['landing']
        if pattern:
            group['filter'] = pattern
    config['proxy-groups'] = [
        {'name': FRONT_GROUP, 'type': 'select', 'proxies': [AUTO_GROUP],
         'use': ['front']},
        {'name': AUTO_GROUP, 'type': 'url-test', 'url': CHECK_URL, 'interval': 180,
         'timeout': 5000, 'expected-status': 204, 'tolerance': 30, 'lazy': False,
         'use': ['front']},
        {'name': GLOBAL_GROUP, 'type': 'select',
         'proxies': [g['name'] for g in region_groups] + ['DIRECT']},
    ] + region_groups
    return config


def build(base, records, mapping):
    """Return (front_config, landing_config, chain_config, summary)."""
    fronts = select_fronts(records, mapping)
    landings = select_landings(records, mapping)
    summary = {
        'fronts': len(fronts),
        'landings': len(landings),
        'chain_enabled': bool(fronts and landings),
    }
    front_config = render_front(base, fronts) if fronts else None
    landing_config = render_landing(base, landings) if landings else None
    chain_config = render_chain(base) if (fronts and landings) else None
    return front_config, landing_config, chain_config, summary
