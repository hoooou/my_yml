#!/usr/bin/env python3
"""Build the three chain products from the same measurement records.

- 前置配置.yaml : fronts only, grouped by region
- 后置配置.yaml : landings only, grouped by region, no CN-reachability gate
- 链式配置.yaml : no nodes, two proxy-providers + groups, rules copied from 优选配置

--- @ty.aicoding@1793205643486 ---
"""

import copy
import ipaddress
import math
import socket
from urllib.parse import quote

FRONT_REGIONS = ('HK', 'JP', 'KR', 'SG')
FRONT_LABELS = {'HK': '香港', 'JP': '日本', 'KR': '韩国', 'SG': '新加坡'}
EU_PREFIXES = ('英国', '德国', '法国', '荷兰', '意大利', '西班牙', '葡萄牙', '波兰', '瑞典',
               '瑞士', '芬兰', '挪威', '丹麦', '爱尔兰', '奥地利', '比利时', '捷克',
               '罗马尼亚', '匈牙利', '希腊', '乌克兰', '俄罗斯', '爱沙尼亚', '拉脱维亚',
               '立陶宛', '冰岛', '卢森堡', '保加利亚', '克罗地亚', '塞尔维亚', '斯洛伐克',
               '斯洛文尼亚')
BASE_KEYS = ('mixed-port', 'allow-lan', 'mode', 'log-level', 'external-controller',
             'dns', 'rules', 'rule-providers', 'find-process-mode', 'ipv6', 'sniffer')
CHECK_URL = 'http://www.gstatic.com/generate_204'
FRONT_PREFIX = '🛫 '
FRONT_GROUP = '🌉 前置'
AUTO_GROUP = '🔄 自动前置'
GLOBAL_GROUP = '🚀 全局选择'
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


def lookup_server_countries(servers, timeout=15, pause=5):
    """Geolocate entry servers; unknown hosts are skipped."""
    import requests

    resolved = {}
    for server in sorted({str(s) for s in servers if s}):
        try:
            ipaddress.ip_address(server)
            resolved[server] = server
            continue
        except ValueError:
            pass
        try:
            info = socket.getaddrinfo(server, None, proto=socket.IPPROTO_TCP)
        except OSError:
            continue
        if info:
            resolved[server] = info[0][4][0]
    codes = {}
    unique = sorted(set(resolved.values()))
    for offset in range(0, len(unique), 100):
        batch = unique[offset:offset + 100]
        try:
            response = requests.post('http://ip-api.com/batch',
                                     params={'fields': 'query,countryCode,status'},
                                     json=batch, timeout=timeout)
            response.raise_for_status()
            for item in response.json():
                if isinstance(item, dict) and item.get('status') == 'success':
                    codes[item.get('query')] = item.get('countryCode')
        except (requests.RequestException, ValueError):
            continue
        if offset + 100 < len(unique):
            import time
            time.sleep(pause)
    return {server: codes.get(ip) for server, ip in resolved.items() if codes.get(ip)}


def _landing_gates(record, mapping):
    """Strict landing gates; domestic TCP reachability is deliberately absent."""
    from availability import required_websites_passed
    import app_tls
    import stability

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
    if (record.get('upload_precheck') or {}).get('status') != 'passed':
        return False
    if record.get('stability') is not None and not stability.passed(record.get('stability')):
        return False
    if record.get('id') not in mapping:
        return False
    return True


def front_region(record, node, countries):
    """Entry-server country when known; fall back to the measured exit country."""
    country = (countries or {}).get(str(node.get('server')))
    if country is not None:
        return country if country in FRONT_REGIONS else None
    fallback = (record.get('exit') or {}).get('country_code')
    return fallback if fallback in FRONT_REGIONS else None


def _front_gates(record, mapping, countries):
    from availability import tcp_supported

    node = mapping.get(record.get('id'))
    if not node or not tcp_supported(node):
        return False
    if (record.get('entry') or {}).get('status') != 'passed':
        return False
    if front_region(record, node, countries) is None:
        return False
    if (record.get('website_tls') or {}).get('status') != 'passed':
        return False
    if (record.get('upload_precheck') or {}).get('status') != 'passed':
        return False
    if (record.get('download') or {}).get('status') != 'passed':
        return False
    probe = record.get('front_probe') or {}
    if (probe.get('cn') or {}).get('status') != 'passed':
        return False
    if (probe.get('intl') or {}).get('status') != 'passed':
        return False
    if (probe.get('down10') or {}).get('status') != 'passed':
        return False
    if (probe.get('down100') or {}).get('status') != 'passed':
        return False
    return True


def _front_speed(record):
    speed = ((record.get('front_probe') or {}).get('down100') or {}).get('speed_mib_s')
    return speed if isinstance(speed, (int, float)) else -1


def select_fronts(records, mapping, countries=None, trim=0.2, min_sample=5):
    """Keep every front that passes; trim the slowest 20% inside each region."""
    picked, seen = [], set()
    for record in records:
        if not _front_gates(record, mapping, countries):
            continue
        node = mapping[record['id']]
        key = endpoint(node)
        if key in seen:
            continue
        seen.add(key)
        picked.append({'record': record, 'node': node,
                       'region': front_region(record, node, countries)})
    kept = []
    for region in FRONT_REGIONS:
        bucket = [item for item in picked if item['region'] == region]
        if len(bucket) >= min_sample and trim > 0:
            bucket.sort(key=_front_speed, reverse=True)
            bucket = bucket[:max(1, len(bucket) - math.ceil(len(bucket) * trim))]
        kept.extend(bucket)
    kept.sort(key=lambda item: (FRONT_REGIONS.index(item['region']),
                               -_front_speed(item['record']),
                               (item['record'].get('entry') or {}).get('latency_ms') or 1e9))
    return kept


def select_landings(records, mapping):
    nodes, seen = [], set()
    for record in records:
        if not _landing_gates(record, mapping):
            continue
        node = mapping[record['id']]
        key = endpoint(node)
        if key in seen or is_cloudflare(node.get('server')):
            continue
        seen.add(key)
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
    counters, nodes, per_region = {}, [], {}
    for item in fronts:
        region = item['region']
        counters[region] = counters.get(region, 0) + 1
        entry = (item['record'].get('entry') or {}).get('latency_ms')
        speed = (item['record'].get('download') or {}).get('speed_mib_s')
        bandwidth = f"{speed * 8:.0f}Mbps" if isinstance(speed, (int, float)) else '?Mbps'
        entry_text = f"{int(entry)}ms" if isinstance(entry, (int, float)) else '?ms'
        name = f"{FRONT_PREFIX}{FRONT_LABELS[region]}{counters[region]:02d}|{entry_text}|{bandwidth}"
        node = copy.deepcopy(item['node'])
        node['name'] = name
        nodes.append(node)
        label = {'HK': '🇭🇰 香港', 'JP': '🇯🇵 日本',
                 'KR': '🇰🇷 韩国', 'SG': '🇸🇬 新加坡'}[region]
        per_region.setdefault(label, []).append(name)
    config['proxies'] = nodes
    config['proxy-groups'] = [
        {'name': GLOBAL_GROUP, 'type': 'select',
         'proxies': list(per_region) + ['DIRECT']},
    ] + [_group(label, members) for label, members in per_region.items()]
    return config


def render_landing(base, landings):
    config = _base(base)
    config['ipv6'] = False
    config.setdefault('dns', {})['ipv6'] = False
    config['proxies'] = [copy.deepcopy(node) for node in landings]
    names = [node['name'] for node in config['proxies']]
    eu = [n for n in names if str(n).startswith(EU_PREFIXES)]
    groups = [
        _group('🇺🇸 美国', [n for n in names if str(n).startswith('美国')]),
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
        _group('🇺🇸 美国', []), _group('🇯🇵 日本', []), _group('🇸🇬 新加坡', []),
        _group('🇪🇺 欧洲', []), _group('🌐 全部节点', []),
    ]
    for group in region_groups:
        group.pop('proxies', None)
        group['use'] = ['landing']
    region_groups[0]['filter'] = '^美国'
    region_groups[1]['filter'] = '^日本'
    region_groups[2]['filter'] = '^新加坡'
    region_groups[3]['filter'] = '^(' + '|'.join(EU_PREFIXES) + ')'
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


def build(base, records, mapping, *, countries=None, geo_lookup=None):
    """Return (front_config, landing_config, chain_config, summary).

    Region uses the entry-server country when provided; otherwise the measured
    exit country is used (documented limitation until server geolocation is wired).
    """
    if countries is None and geo_lookup is not None:
        servers = {mapping[r['id']].get('server') for r in records
                   if r.get('id') in mapping and (r.get('entry') or {}).get('status') == 'passed'}
        countries = geo_lookup(servers)
    countries = countries or {}
    fronts = select_fronts(records, mapping, countries)
    landings = select_landings(records, mapping)
    summary = {
        'fronts': len(fronts),
        'front_regions': {label: sum(1 for f in fronts if f['region'] == code)
                          for code, label in FRONT_LABELS.items()},
        'landings': len(landings),
        'chain_enabled': bool(fronts and landings),
    }
    front_config = render_front(base, fronts) if fronts else None
    landing_config = render_landing(base, landings) if landings else None
    chain_config = render_chain(base) if (fronts and landings) else None
    return front_config, landing_config, chain_config, summary
