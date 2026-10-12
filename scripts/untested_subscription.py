"""Append an explicitly authorized subscription only at final publication.

Only proxy definitions are accepted. Source routing, DNS and instructions are
ignored. Nothing here connects to, probes, or scores a proxy endpoint.
"""
import copy
import json
import os
from urllib.parse import urlsplit

import requests
import yaml
from select_nodes import canonical_node

GROUP = '🍓 小草莓（免测）'
MAX_BYTES = 5 * 1024 * 1024


def fetch_nodes(url):
    if urlsplit(url).scheme != 'https':
        raise ValueError('免测订阅必须使用HTTPS')
    try:
        with requests.Session() as client:
            client.max_redirects = 3
            with client.get(url, headers={'User-Agent': 'mihomo/1.19.32', 'Cache-Control': 'no-cache'},
                            timeout=(10, 25), stream=True) as response:
                response.raise_for_status()
                body = bytearray()
                for chunk in response.iter_content(65536):
                    body.extend(chunk)
                    if len(body) > MAX_BYTES:
                        raise ValueError('免测订阅超过大小上限')
        content = yaml.safe_load(bytes(body))
        nodes = content.get('proxies') if isinstance(content, dict) else None
        if not isinstance(nodes, list) or not nodes:
            raise ValueError('免测订阅缺少非空proxies列表')
        return nodes
    except (requests.RequestException, yaml.YAMLError, ValueError):
        # Requests/YAML exceptions can contain the secret URL or credentials.
        raise ValueError('免测订阅获取或解析失败；保留原订阅') from None


def identity(node):
    canonical = canonical_node(node)
    if canonical is None:
        raise ValueError('免测订阅存在不完整或依赖其他代理的节点；保留原订阅')
    canonical.pop('delay', None)
    return json.dumps(canonical, ensure_ascii=False, sort_keys=True, default=str)


def append_nodes(config, nodes):
    result = copy.deepcopy(config)
    existing = {identity(node): node['name'] for node in result['proxies']}
    names = {n['name'] for n in result['proxies']} | {g['name'] for g in result['proxy-groups']}
    private_names, seen = [], set()
    added = duplicates = 0
    for index, source in enumerate(nodes, 1):
        key = identity(source)
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        if key in existing:
            name = existing[key]
            duplicates += 1
        else:
            node = copy.deepcopy(source)
            original = source.get('name') or f'节点{index:02d}'
            name = f'🍓 {original}'
            suffix = 2
            while name in names:
                name = f'🍓 {original} ({suffix})'; suffix += 1
            node['name'] = name
            result['proxies'].append(node)
            existing[key] = name; names.add(name); added += 1
        private_names.append(name)
    # No URL-test/health-check is attached to this manually selectable pool.
    result['proxy-groups'].append({'name': GROUP, 'type': 'select', 'proxies': private_names})
    for group in result['proxy-groups']:
        if group['name'] == '🚀 全局选择':
            group['proxies'].insert(max(0, len(group['proxies']) - 1), GROUP)
    info = {'status': 'appended_without_testing', 'group': GROUP, 'source_node_count': len(nodes),
            'node_count': len(private_names), 'added_node_count': added, 'duplicates': duplicates,
            'tested': False, 'names_preserved_with_source_prefix': True}
    return result, info


def append_from_env(config):
    url = os.environ.get('UNTESTED_SUBSCRIPTION_URL', '').strip()
    if not url:
        return config, {'status': 'not_configured', 'added_node_count': 0, 'node_count': 0, 'tested': False}
    return append_nodes(config, fetch_nodes(url))
