#!/usr/bin/env python3
"""Build an optional chained subscription (front -> landing) from the same records.

Fronts are chosen by China-side TCP reachability, entry-server region and
website availability, then verified by an actual front -> landing chain run.
The result is written as a **separate** file; 优选配置.yaml is never modified.

--- @ty.aicoding@1793178193005 ---
"""

import concurrent.futures as futures
import copy
import ipaddress
import json
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import quote

import requests
import yaml

FRONT_REGIONS = {'HK': '香港', 'JP': '日本', 'SG': '新加坡'}
FRONT_PREFIX = '🛫 '
FRONT_GROUP = '🌉 前置'
MIN_FRONTS = 3
CHECK_URL = 'http://www.gstatic.com/generate_204'
UDP_ONLY = {'hysteria', 'hysteria2', 'tuic', 'wireguard'}


def endpoint_key(node):
    """Same identity the main pipeline uses: lowercase server + port."""
    return str(node.get('server', '')).lower().rstrip('.'), int(node.get('port') or 0)


def tcp_capable(node):
    """Pure-UDP transports cannot carry a TCP dial to the landing."""
    return str(node.get('type', '')).lower() not in UDP_ONLY


def website_sites_passed(record, minimum=1):
    """Lazy import keeps this module free of an import cycle with availability."""
    from availability import website_access_count
    return website_access_count(record) >= minimum


def lookup_countries(hosts, timeout=15, pause=5):
    """Resolve hosts and return {host: ISO country code}; unknown hosts are skipped."""
    resolved = {}
    for host in sorted({str(h) for h in hosts if h}):
        try:
            ipaddress.ip_address(host)
            resolved[host] = host
            continue
        except ValueError:
            pass
        try:
            info = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except OSError:
            continue
        if info:
            resolved[host] = info[0][4][0]

    unique = sorted(set(resolved.values()))
    codes = {}
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
            time.sleep(pause)
    return {host: codes.get(ip) for host, ip in resolved.items() if codes.get(ip)}


def select_candidates(records, mapping, countries, *, limit_per_region=10, total_limit=30, min_sites=1):
    """Filter measurement records down to front candidates, de-duplicated by endpoint."""
    per_region, seen = {}, set()
    for record in records:
        node = mapping.get(record.get('id'))
        if not node or not tcp_capable(node):
            continue
        if (record.get('entry') or {}).get('status') != 'passed':
            continue
        if (record.get('website_tls') or {}).get('status') != 'passed':
            continue
        if not website_sites_passed(record, min_sites):
            continue
        region = countries.get(str(node.get('server')))
        if region not in FRONT_REGIONS:
            continue
        key = endpoint_key(node)
        if key in seen:
            continue
        bucket = per_region.setdefault(region, [])
        if len(bucket) >= limit_per_region:
            continue
        seen.add(key)
        bucket.append({'record': record, 'node': node, 'region': region})
    ordered = []
    for region in FRONT_REGIONS:
        bucket = sorted(per_region.get(region, []),
                        key=lambda item: ((item['record'].get('entry') or {}).get('latency_ms') or 1e9,
                                          item['record'].get('id', '')))
        ordered.extend(bucket)
    return ordered[:total_limit]


def _free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def _wait_api(port, timeout=25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            requests.get(f'http://127.0.0.1:{port}/version', timeout=2)
            return True
        except requests.RequestException:
            time.sleep(0.5)
    return False


def verify_chains(fronts, landings, binary, root, *, rounds=2, concurrency=20,
                  timeout_ms=5000, gap_seconds=60):
    """Run every front x landing pair through mihomo and collect success/latency."""
    if not fronts or not landings or not binary:
        return {}
    port = _free_port()
    proxies, pairs, order = [], {}, []
    for index, front in enumerate(fronts):
        node = copy.deepcopy(front['node'])
        node['name'] = f"F{index:02d}"
        proxies.append(node)
    for landing_index, landing in enumerate(landings):
        for front_index, _front in enumerate(fronts):
            node = copy.deepcopy(landing['node'])
            name = f"P{landing_index:03d}-{front_index:02d}"
            node['name'] = name
            node['dialer-proxy'] = f"F{front_index:02d}"
            proxies.append(node)
            pairs[name] = (front_index, landing_index)
            order.append(name)
    config = {
        'mixed-port': _free_port(), 'allow-lan': False, 'mode': 'rule', 'log-level': 'warning',
        'external-controller': f'127.0.0.1:{port}', 'secret': '',
        'dns': {'enable': True, 'nameserver': ['223.5.5.5', '119.29.29.29']},
        'proxies': proxies, 'rules': ['MATCH,DIRECT'],
    }
    work = Path(root) / 'chain-verify'
    work.mkdir(parents=True, exist_ok=True)
    config_path = work / 'config.yaml'
    config_path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding='utf-8')
    process = subprocess.Popen([binary, '-d', str(work), '-f', str(config_path)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    results = {}
    try:
        if not _wait_api(port):
            raise RuntimeError('链式验证实例未能启动')

        def probe(name):
            try:
                response = requests.get(
                    f'http://127.0.0.1:{port}/proxies/{quote(name)}/delay',
                    params={'url': CHECK_URL, 'timeout': timeout_ms}, timeout=timeout_ms / 1000 + 5)
                if response.status_code == 200:
                    return True, response.json().get('delay')
            except (requests.RequestException, ValueError):
                pass
            return False, None

        for round_index in range(rounds):
            if round_index and gap_seconds:
                time.sleep(gap_seconds)
            with futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
                jobs = {pool.submit(probe, name): name for name in order}
                for job in futures.as_completed(jobs):
                    name = jobs[job]
                    ok, latency = job.result()
                    results.setdefault(name, []).append({'ok': ok, 'latency_ms': latency})
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
    return {name: results.get(name, []) for name in pairs}


def summarise(fronts, landing_count, pair_results, rounds):
    """Aggregate per-front reachability across rounds."""
    rows = []
    for index, front in enumerate(fronts):
        observed = [values for name, values in pair_results.items()
                    if name.endswith(f'-{index:02d}') for values in [values]]
        reachable = []
        latencies = []
        for values in observed:
            hits = [v for v in values if v.get('ok')]
            reachable.append(len(hits))
            latencies.extend(v['latency_ms'] for v in hits if v.get('latency_ms'))
        rows.append({
            'front': front,
            'reachable_by_round': reachable,
            'best_reachable': max(reachable) if reachable else 0,
            'median_latency_ms': sorted(latencies)[len(latencies) // 2] if latencies else None,
        })
    rows.sort(key=lambda row: (-row['best_reachable'],
                               row['median_latency_ms'] if row['median_latency_ms'] is not None else 1e9,
                               (row['front']['record'].get('entry') or {}).get('latency_ms') or 1e9))
    return rows


def render(base_config, rows):
    """Return a new config with front nodes, a front group and dialer-proxy wiring."""
    config = copy.deepcopy(base_config)
    front_nodes = []
    counters = {}
    ordered = [row for row in rows if row['best_reachable'] > 0]
    for row in ordered:
        record, node, region = row['front']['record'], row['front']['node'], row['front']['region']
        counters[region] = counters.get(region, 0) + 1
        entry = (record.get('entry') or {}).get('latency_ms')
        name = f"{FRONT_PREFIX}{FRONT_REGIONS[region]}{counters[region]:02d}|" \
               f"{int(entry) if entry else '?'}ms|{row['best_reachable']}落地"
        copy_node = copy.deepcopy(node)
        copy_node['name'] = name
        front_nodes.append(copy_node)
    config['proxies'] = front_nodes + config['proxies']
    for node in config['proxies']:
        if not str(node.get('name', '')).startswith(FRONT_PREFIX):
            node['dialer-proxy'] = FRONT_GROUP
    group = {
        'name': FRONT_GROUP, 'type': 'url-test', 'url': CHECK_URL,
        'interval': 300, 'timeout': 5000, 'expected-status': 204,
        'tolerance': 50, 'lazy': False,
        'proxies': [node['name'] for node in front_nodes],
    }
    config['proxy-groups'] = [group] + config['proxy-groups']
    return config


def build(base_config, records, mapping, *, binary=None, root=None, limit_per_region=10,
          total_limit=30, min_sites=1, rounds=2, concurrency=20, timeout_ms=5000,
          gap_seconds=60, geo_lookup=lookup_countries, verifier=verify_chains, logger=print):
    """Select fronts, verify them against every published US landing, render a config."""
    published = {node.get('name'): node for node in base_config.get('proxies', [])}
    landings = [{'node': node} for name, node in published.items()
                if str(name).startswith('美国')]
    if not landings:
        return None, {'enabled': False, 'reason': 'no_us_landing'}
    hosts = {mapping[r['id']].get('server') for r in records
             if r.get('id') in mapping and (r.get('entry') or {}).get('status') == 'passed'}
    countries = geo_lookup(hosts)
    candidates = select_candidates(records, mapping, countries,
                                   limit_per_region=limit_per_region,
                                   total_limit=total_limit, min_sites=min_sites)
    if len(candidates) < MIN_FRONTS:
        return None, {'enabled': False, 'reason': 'front_pool_too_small',
                      'candidates': len(candidates)}
    if binary:
        pair_results = verifier(candidates, landings, binary, root, rounds=rounds,
                                concurrency=concurrency, timeout_ms=timeout_ms,
                                gap_seconds=gap_seconds)
        rows = summarise(candidates, len(landings), pair_results, rounds)
    else:
        rows = [{'front': item, 'reachable_by_round': [], 'best_reachable': 1,
                 'median_latency_ms': None} for item in candidates]
    survivors = [row for row in rows if row['best_reachable'] > 0]
    summary = {
        'enabled': len(survivors) >= MIN_FRONTS,
        'candidates': len(candidates), 'landings_tested': len(landings),
        'rounds': rounds, 'survivors': len(survivors),
        'eliminated': [row['front']['record'].get('id') for row in rows if row['best_reachable'] == 0],
        'regions': {FRONT_REGIONS[item['region']]: sum(1 for row in survivors if row['front']['region'] == item['region'])
                    for item in candidates},
        'fronts': [{'name': row['front']['record'].get('id'), 'region': row['front']['region'],
                    'reachable_by_round': row['reachable_by_round'],
                    'median_latency_ms': row['median_latency_ms']} for row in survivors],
    }
    if len(survivors) < MIN_FRONTS:
        summary['reason'] = 'survivors_too_few'
        return None, summary
    return render(base_config, survivors), summary
