#!/usr/bin/env python3
"""Build the three chain products from the same measurement records.

- 前置配置.yaml : fronts only, one flat url-test group
- 后置配置.yaml : landings only, grouped by region, no CN-reachability gate
- 链式配置.yaml : fronts + landings inlined (no proxy-provider), groups by region, rules copied

--- @ty.aicoding@1793205643486 ---
"""

import copy
import ipaddress
import re
import math
import socket

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
# 用户自己的订阅：流水线拉下来当免测前置用，直接写进配置；客户端不再需要拉 provider。
# 注意：地址写在仓库里，token 会随仓库公开。
EXT_SUB_URL = 'https://vs.yieti.top/sub?token=e6f485b6ba8929fa37ea6eddebb3ab87&clash'
EXT_GROUP = '🛫 yieti'
EXT_AUTO_GROUP = '🛫 yieti 自动'
EXT_AUTO_SIZE = 15  # 自动组最多放这么多个
EXT_AUTO_PER_REGION = 3  # 每个地区最多挑这么多个
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
    # 前置的排序：优选域名型的（server 是域名）优先，其次看国内 TCP 延迟，最后才看下载速度。
    # 前置只是跳板，国内 RTT 比节点自身的下载速度更影响体感。
    picked.sort(key=lambda item: (0 if is_domain_server(item['node']) else 1,
                                  (item['record'].get('entry') or {}).get('latency_ms') or 1e9,
                                  -_front_speed(item['record'])))
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


def _group(name, nodes):
    return {'name': name, 'type': 'url-test', 'url': CHECK_URL, 'interval': 120,
            'timeout': 3000, 'expected-status': 204, 'tolerance': 100, 'lazy': False,
            'proxies': nodes}


_EXTERNAL_CACHE = {}


def previous_external_fronts(path='链式配置.yaml'):
    """上一版链式配置里的订阅节点；订阅拉取失败时用它顶上，避免整组消失。"""
    import yaml
    from pathlib import Path

    try:
        data = yaml.safe_load(Path(path).read_text(encoding='utf-8'))
        group = next(g for g in data['proxy-groups'] if g['name'] == EXT_GROUP)
        names = [name for name in group.get('proxies') or [] if name != EXT_AUTO_GROUP]
        by_name = {node['name']: node for node in data.get('proxies') or []}
    except Exception:
        return []
    return [copy.deepcopy(by_name[name]) for name in names if name in by_name]


def external_fronts(url=EXT_SUB_URL):
    """拉取自有的 Clash 订阅，按免测前置返回；拉不到就返回空，不影响其他产物。"""
    import os
    import yaml
    from select_nodes import session

    if os.environ.get('CHAIN_EXTERNAL_SUB') == 'off':
        return []
    if url in _EXTERNAL_CACHE:
        return copy.deepcopy(_EXTERNAL_CACHE[url])
    data = None
    for attempt in range(3):
        try:
            with session() as client:
                # 面板按 UA 拦人：默认的 python-requests UA 直接 400，要用客户端自己的 UA。
                # 订阅有几百 KB，读超时要给够，否则 runner 上会偶发超时。
                response = client.get(url, timeout=(5, 30), headers={'User-Agent': 'clash-verge/v1.0'})
                response.raise_for_status()
                data = yaml.safe_load(response.text)
            break
        except Exception as error:
            if attempt == 2:
                reason = '订阅返回 404，通常是当日额度用尽' if '404' in str(error) else '订阅拉取失败'
                print(f'{reason}，沿用上一版的订阅节点', flush=True)
    if data is None:
        nodes = previous_external_fronts()
        _EXTERNAL_CACHE[url] = nodes
        return copy.deepcopy(nodes)
    nodes, seen, names = [], set(), set()
    for node in (data or {}).get('proxies') or []:
        if not isinstance(node, dict) or not node.get('server') or not node.get('type'):
            continue
        key = (node.get('type'), node.get('server'), node.get('port'))
        if key in seen:
            continue
        seen.add(key)
        item = copy.deepcopy(node)
        name = str(node.get('name') or f'{len(nodes) + 1:02d}')
        while name in names:
            name += '·'
        names.add(name)
        item['name'] = name
        nodes.append(item)
    _EXTERNAL_CACHE[url] = nodes
    return copy.deepcopy(nodes)


EXT_REGION_TOKENS = (
    ('HK', ('HK', '香港')), ('TW', ('TW', '台湾', '臺灣')), ('JP', ('JP', '日本')),
    ('SG', ('SG', '新加坡', '狮城')), ('KR', ('KR', '韩国')), ('US', ('US', '美国')),
    ('UK', ('UK', 'GB', '英国')), ('DE', ('DE', '德国')),
)


def ext_region(name):
    """地区只看名字里的标记；名字里没有地区标记的归到 CF/其他。"""
    text = str(name).upper()
    for region, tokens in EXT_REGION_TOKENS:
        if any(token in text for token in tokens):
            return region
    return 'CF' if 'CF' in text else '其他'


def is_domain_server(node):
    """server 写的是域名（优选域名）而不是 IP，这类节点在国内通常更容易通。"""
    host = str(node.get('server') or '').strip()
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True
    return False


def pick_ext_auto(nodes, latencies, per_region=EXT_AUTO_PER_REGION, limit=EXT_AUTO_SIZE):
    """优先挑优选域名型节点，再按地区轮着挑：先每个地区拿最快的，再拿第二快的。"""
    preferred = [node for node in nodes if is_domain_server(node)]
    pool = preferred if len(preferred) >= limit else list(nodes)
    buckets = {}
    for index, node in enumerate(pool):
        penalty = 0.0 if is_domain_server(node) else 100000.0
        buckets.setdefault(ext_region(node.get('name')), []).append(
            (penalty + latencies.get(node['name'], float('inf')), index, node))
    for items in buckets.values():
        items.sort(key=lambda item: (item[0], item[1]))
    picked, round_index = [], 0
    while len(picked) < limit:
        candidates = [key for key, items in buckets.items() if len(items) > round_index]
        if not candidates:
            break
        candidates.sort(key=lambda key: (buckets[key][round_index][0], key))
        for key in candidates:
            if len(picked) >= limit:
                break
            if len(picked) and sum(1 for node in picked if ext_region(node.get('name')) == key) >= per_region:
                continue
            picked.append(buckets[key][round_index][2])
        round_index += 1
    return picked


_LATENCY_CACHE = {}


def ext_latencies(nodes, per_second=25):
    """用 xxapi 的 TCP 探测拿真实延迟（名字里的数字不可信）；限流就停。"""
    import os
    import time
    from availability import XXAPI, Pace, parse_xxapi
    from select_nodes import session

    if os.environ.get('CHAIN_EXTERNAL_SUB') == 'off':
        return {}
    key = tuple((node.get('name'), node.get('server'), node.get('port')) for node in nodes)
    if key in _LATENCY_CACHE:
        return dict(_LATENCY_CACHE[key])
    pace = Pace(1 / per_second)
    values, client = {}, None
    try:
        client = session().__enter__()
        for node in nodes:
            host, port = str(node.get('server', '')), int(node.get('port') or 0)
            if not host or not port or not pace.wait():
                continue
            try:
                response = client.get(XXAPI, params={'address': host, 'port': port}, timeout=(5, 10))
                if response.status_code == 429:
                    print('xxapi 限流，后面的订阅节点不再测速', flush=True)
                    break
                response.raise_for_status()
                parsed = parse_xxapi(response.json(), host, port)
            except Exception:
                continue
            if parsed.get('status') == 'passed':
                values[node.get('name')] = parsed['latency_ms']
            time.sleep(0)
    finally:
        if client is not None:
            client.close()
    _LATENCY_CACHE[key] = dict(values)
    return values


def ext_auto_names(nodes):
    if not nodes:
        return []
    return [node['name'] for node in pick_ext_auto(nodes, ext_latencies(nodes))]


def _front_nodes(fronts):
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
    return nodes, names


def render_front(base, fronts):
    config = _base(base)
    config['ipv6'] = False
    config.setdefault('dns', {})['ipv6'] = False
    nodes, names = _front_nodes(fronts)
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


def render_chain(base, fronts, landings, ext_fronts=()):
    """节点全部内联，不用 proxy-provider：客户端拉不到 provider 时链式会整组为空。"""
    config = _base(base)
    config['ipv6'] = False
    config.setdefault('dns', {})['ipv6'] = False
    front_nodes, front_names = _front_nodes(fronts)
    landing_nodes = [copy.deepcopy(node) for node in landings]
    ext_nodes = [copy.deepcopy(node) for node in ext_fronts]
    taken = set(front_names) | {node['name'] for node in landing_nodes}
    for node in ext_nodes:
        while node['name'] in taken:
            node['name'] += '·'
        taken.add(node['name'])
    ext_names = [node['name'] for node in ext_nodes]
    for node in landing_nodes:
        # 原来的 landing provider 用 override 挂前置，内联后逐个节点挂。
        node['dialer-proxy'] = FRONT_GROUP
    names = [node['name'] for node in landing_nodes]
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
    config['proxies'] = front_nodes + ext_nodes + landing_nodes
    front_choices = [AUTO_GROUP]
    if ext_names:
        # 订阅节点单独一组，手动选择、不参与自动测速。
        front_choices.append(EXT_GROUP)
    # 订阅节点：自动那一项按顺序兜底（fallback，只看通不通），其余节点仍可手动强制。
    ext_groups = []
    if ext_names:
        # 自动组只放挑出来的十几个，url-test 自动选最快的；lazy 让没用它的时候不探测。
        ext_auto = _group(EXT_AUTO_GROUP, ext_auto_names(ext_nodes))
        ext_auto.update(interval=300, lazy=True)
        ext_groups = [ext_auto, {'name': EXT_GROUP, 'type': 'select',
                                 'proxies': [EXT_AUTO_GROUP] + ext_names,
                                 'default-selected': EXT_AUTO_GROUP}]
    # 需要手动选的组放前面（前置、yieti、全局），自动跑的在下面。
    manual = [{'name': FRONT_GROUP, 'type': 'select', 'proxies': front_choices}]
    manual += [g for g in ext_groups if g['type'] == 'select']
    manual.append({'name': GLOBAL_GROUP, 'type': 'select',
                   'proxies': [g['name'] for g in groups] + ['DIRECT']})
    automatic = [_group(AUTO_GROUP, front_names)]
    automatic += [g for g in ext_groups if g['type'] != 'select']
    config['proxy-groups'] = manual + automatic + groups
    return config


def build(base, records, mapping, ext_fronts=()):
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
    chain_config = render_chain(base, fronts, landings, ext_fronts) if (fronts and landings) else None
    return front_config, landing_config, chain_config, summary
