"""Export separate native v2rayN 7.24 profiles using its version-4 inner URI.

Reference: 2dust/v2rayN tag 7.24.4, InnerFmt/ProfileItem/TransportExtraItem.
No Custom configuration is emitted and no proxy type is silently substituted.
"""
import base64
import json
from pathlib import Path

TYPES = {'vmess': (1, 'vmess'), 'ss': (3, 'shadowsocks'), 'socks5': (4, 'socks'),
         'vless': (5, 'vless'), 'trojan': (6, 'trojan'), 'http': (10, 'http')}
COMMON = {'name', 'type', 'server', 'port', 'username', 'password', 'uuid', 'tls',
          'sni', 'servername', 'skip-cert-verify', 'alpn', 'client-fingerprint',
          'network', 'udp', 'delay', 'xudp', 'encryption', 'flow', 'cipher', 'alterId',
          'ws-opts', 'http-opts', 'grpc-opts', 'xhttp-opts', 'reality-opts'}
# Subscription metadata has no effect on native connection settings.
ANNOTATIONS = {'country'}


def _limited(options, allowed, label):
    if set(options) - set(allowed):
        raise ValueError('v2rayN原生导出暂不支持' + label + '中的字段：' + ','.join(sorted(set(options) - set(allowed))))


def profile(node):
    kind = node['type']
    if kind not in TYPES:
        raise ValueError('v2rayN原生导出暂不支持协议：' + kind)
    _limited(node, COMMON | ANNOTATIONS, kind)
    result = {'ConfigVersion': 4, 'ConfigType': TYPES[kind][0], 'CoreType': 2,
              'Remarks': node['name'], 'Address': str(node['server']), 'Port': int(node['port']),
              'Network': 'raw', 'MuxEnabled': False,
              'Username': str(node.get('username') or ''),
              'Password': str(node.get('uuid') if kind in ('vless', 'vmess') else node.get('password') or ''),
              'StreamSecurity': 'tls' if node.get('tls', kind == 'trojan') else '',
              'AllowInsecure': 'true' if node.get('skip-cert-verify', False) else 'false',
              'Sni': str(node.get('servername') or node.get('sni') or ''),
              'Alpn': ','.join(node.get('alpn') or []),
              'Fingerprint': str(node.get('client-fingerprint') or '')}
    if not result['Address'] or not 0 < result['Port'] < 65536:
        raise ValueError('v2rayN原生节点地址或端口无效')
    protocol = {}
    if kind == 'vless':
        protocol = {'Flow': node.get('flow', ''), 'VlessEncryption': node.get('encryption', 'none')}
    elif kind == 'vmess':
        protocol = {'AlterId': str(node.get('alterId', 0)), 'VmessSecurity': node.get('cipher', 'auto')}
    elif kind == 'ss':
        protocol = {'SsMethod': node['cipher']}
    if node.get('reality-opts'):
        options = node['reality-opts']; _limited(options, ('public-key', 'short-id'), 'reality')
        result.update(StreamSecurity='reality', PublicKey=options['public-key'], ShortId=options.get('short-id', ''))
    transport = {}
    network = node.get('network', 'tcp')
    if network in ('tcp', 'raw', 'http'):
        if network == 'http':
            options = node.get('http-opts') or {}
            _limited(options, ('headers', 'path', 'method'), 'http-opts')
            if options.get('method', 'GET') != 'GET':
                raise ValueError('v2rayN原生HTTP伪装仅支持GET')
            headers = options.get('headers') or {}; _limited(headers, ('Host',), 'HTTP伪装headers')
            hosts = headers.get('Host') or []
            paths = options.get('path') or ['/']
            transport = {'RawHeaderType': 'http', 'Host': ','.join(hosts) if isinstance(hosts, list) else hosts,
                         'Path': ','.join(paths) if isinstance(paths, list) else paths}
    elif network == 'ws':
        options = node.get('ws-opts') or {}; _limited(options, ('headers', 'path'), 'ws-opts')
        headers = options.get('headers') or {}; _limited(headers, ('Host',), 'WS headers')
        result['Network'] = 'ws'
        transport = {'Host': headers.get('Host', ''), 'Path': options.get('path', '/')}
    elif network == 'grpc':
        options = node.get('grpc-opts') or {}; _limited(options, ('grpc-service-name',), 'grpc-opts')
        result['Network'] = 'grpc'
        transport = {'GrpcServiceName': options.get('grpc-service-name', '')}
    elif network == 'xhttp':
        options = node.get('xhttp-opts') or {}; _limited(options, ('host', 'path', 'mode', 'extra'), 'xhttp-opts')
        result['Network'] = 'xhttp'
        transport = {'Host': options.get('host', ''), 'Path': options.get('path', '/'),
                     'XhttpMode': options.get('mode', 'auto')}
        if 'extra' in options:
            transport['XhttpExtra'] = json.dumps(options['extra'], ensure_ascii=False, separators=(',', ':'))
    else:
        raise ValueError('v2rayN原生导出暂不支持传输：' + str(network))
    if protocol:
        result['ProtoExtraObj'] = protocol
    if transport:
        result['TransportExtraObj'] = transport
    return result


def render_with_skips(config):
    """Native lines for every node v2rayN can represent exactly, plus the nodes it cannot.

    A node with a field v2rayN has no slot for (e.g. a WS User-Agent header) is left out of the
    native subscription rather than exported with that field silently dropped. The Clash profile
    still carries it, so one unusual node never blocks the whole publication.
    """
    lines, skipped = [], []
    for node in config['proxies']:
        try:
            data = json.dumps(profile(node), ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        except ValueError as error:
            skipped.append({'name': node.get('name'), 'type': node.get('type'), 'reason': str(error)})
            continue
        payload = base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')
        lines.append('v2rayn://' + TYPES[node['type']][1] + '/' + payload)
    if not lines:
        raise ValueError('拒绝发布空v2rayN订阅')
    return '\n'.join(lines) + '\n', skipped


def render(config):
    """Strict form: every node must export exactly (used by tests and callers that require it)."""
    text, skipped = render_with_skips(config)
    if skipped:
        raise ValueError(skipped[0]['reason'])
    return text
