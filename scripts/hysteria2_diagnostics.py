#!/usr/bin/env python3
"""Bounded, read-only HY2 authenticated cloud and domestic UDP comparison."""
import argparse
import concurrent.futures as futures
import copy
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import secrets
import socket
import time

import availability as a
import select_nodes as s

ORIGIN = 'https://www.idcd.com'
DNS_PAYLOAD = bytes.fromhex('123401000001000000000000076578616d706c6503636f6d0000010001')
MAX_UNITS = 40
# Previously observed domestic replies and its obfuscated comparison, only for diagnostic sampling.
KNOWN_SAMPLES = ('n-2e60b13ec05a', 'n-1d4370f209d6')


def choose_samples(nodes, records, limit=4):
    rows = {r['id']: r for r in records}
    candidates = sorted((n for n in nodes if n['type'] == 'hysteria2'
        and n['name'] in rows and rows[n['name']]['precheck']['status'] == 'passed'
        and n.get('obfs', '') in ('', 'salamander') and not n.get('ports')),
        key=lambda n: (n['name'] not in KNOWN_SAMPLES,
                       rows[n['name']]['precheck'].get('median_elapsed_ms') or float('inf'), n['name']))
    # Include both wire formats, then fill with distinct endpoints. No credential-dependent ranking.
    result, seen = [], set()
    for group in (False, True, None):
        for node in candidates:
            key = node['server'], int(node['port'])
            if key in seen or (group is not None and bool(node.get('obfs')) != group):
                continue
            result.append(node); seen.add(key)
            if len(result) == limit:
                return result
            if group is not None:
                break
    return result


def public_address(host):
    addresses = [ipaddress.ip_address(item[4][0]) for item in
                 socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM)]
    if not addresses or any(not ip.is_global for ip in addresses):
        raise ValueError('入口不是可靠的公网地址')
    return str(next((ip for ip in addresses if ip.version == 4), addresses[0]))


def obfuscate(packet, node):
    if not node.get('obfs'):
        return packet
    if node.get('obfs') != 'salamander' or not node.get('obfs-password'):
        raise ValueError('未知混淆或缺少混淆参数')
    salt = secrets.token_bytes(8)
    mask = hashlib.blake2b(str(node['obfs-password']).encode() + salt, digest_size=32).digest()
    return salt + bytes(value ^ mask[i % 32] for i, value in enumerate(packet))


def version_packet(node):
    packet = b'\xc0' + bytes.fromhex('1a2a3a4a') + b'\x08' + secrets.token_bytes(8)
    packet += b'\x08' + secrets.token_bytes(8)
    return obfuscate(packet + secrets.token_bytes(1200 - len(packet)), node)


def clear_packet(packet, node):
    if node.get('obfs') == 'salamander':
        if len(packet) < 8:
            return b''
        mask = hashlib.blake2b(str(node['obfs-password']).encode() + packet[:8], digest_size=32).digest()
        packet = bytes(value ^ mask[i % 32] for i, value in enumerate(packet[8:]))
    return packet


def quic_header(packet):
    if len(packet) < 7 or not packet[0] & 0x80:
        return None
    dest_len = packet[5]
    if dest_len > 20 or len(packet) < 7 + dest_len:
        return None
    source_len = packet[6 + dest_len]
    if source_len > 20 or len(packet) < 7 + dest_len + source_len:
        return None
    offset = 7 + dest_len + source_len
    return {'version': int.from_bytes(packet[1:5], 'big'),
            'dest': packet[6:6 + dest_len], 'source': packet[7 + dest_len:offset], 'offset': offset}


def initial_packet_valid(packet, node):
    packet = clear_packet(packet, node)
    header = quic_header(packet)
    return len(packet) >= 1200 and header is not None and header['version'] in (1, 0x6b3343cf)


def cloud_udp(address, port, packet, node):
    """Independent cloud wire-format control, with QUIC connection-ID matching; no auth claim."""
    result = {'status': 'unknown', 'protocol_verified': False}
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3); sock.connect((address, port))
            start = time.monotonic(); sock.send(packet); reply = sock.recv(65535)
            result.update(rtt_ms=round((time.monotonic() - start) * 1000, 3), response_bytes=len(reply))
        sent = quic_header(clear_packet(packet, node))
        received_packet = clear_packet(reply, node); received = quic_header(received_packet)
        valid = sent is not None and received is not None and received['dest'] == sent['source']
        if valid and received['version'] == 0:
            versions = received_packet[received['offset']:]
            valid = (received['source'] == sent['dest'] and len(versions) >= 4
                     and len(versions) % 4 == 0 and any(int.from_bytes(versions[i:i+4], 'big')
                     in (1, 0x6b3343cf) for i in range(0, len(versions), 4)))
        elif valid:
            valid = received['version'] in (1, 0x6b3343cf)
        result.update(status='quic_reply' if valid else 'unknown_reply', protocol_verified=bool(valid))
    except socket.timeout:
        result.update(status='no_reply', reason='云端UDP单包无回应')
    except OSError:
        result['reason'] = '云端UDP请求异常'
    return result


def capture_initials(binary, root, nodes, rounds=3):
    """Generate each fresh ClientHello against a silent loopback socket; never authenticate there."""
    root.mkdir(parents=True, exist_ok=True)
    sockets, proxies, rows, originals = {}, [], [], {}
    try:
        for node in nodes:
            for round_index in range(rounds):
                key = node['name'] + '-initial-' + str(round_index)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(('127.0.0.1', 0)); sock.settimeout(4)
                sockets[key] = sock; originals[key] = node
                proxy = copy.deepcopy(node)
                proxy.update(name=key, server='127.0.0.1', port=sock.getsockname()[1])
                # Preserve the original TLS destination when replacing only the UDP capture address.
                proxy['sni'] = node.get('sni') or node['server']
                proxy.pop('ports', None)
                proxies.append(proxy); rows.append({'id': key})
        if not rows:
            return {}
        listeners, ports = s.make_listeners(rows)
        packets = {}
        with s.Core(binary, root, proxies, listeners), futures.ThreadPoolExecutor(max_workers=len(rows)) as pool:
            jobs = [pool.submit(a.check_site, ports[row['id']], 'Google204', a.SITES['Google204']) for row in rows]
            for key, sock in sockets.items():
                try:
                    packet, source = sock.recvfrom(65535)
                    if source[0] == '127.0.0.1' and initial_packet_valid(packet, originals[key]):
                        packets[key] = packet
                except socket.timeout:
                    pass
            for job in jobs:
                job.result()
        return packets
    finally:
        for sock in sockets.values():
            sock.close()


def choose_probes(data):
    candidates = [n for n in data.get('data', {}).get('nodes', []) if
        n.get('country_code') == 'CN' and n.get('status') == 'active'
        and 'udp' in n.get('capabilities', []) and n.get('kind') == 'probe']
    result = []
    for token in ('移动', '电信'):
        matches = sorted((n for n in candidates if token in n.get('name', '')), key=lambda n: n['id'])
        if matches:
            n = matches[0]
            result.append({key: n.get(key) for key in ('id', 'name', 'country_code', 'isp', 'asn', 'city')})
    return result


def parse_result(data, node_id, address, port):
    """Validate provider identity; a UDP reply never becomes production entry=passed."""
    result = {'status': 'unknown', 'probe_id': node_id, 'protocol_verified': False}
    task = data.get('data') if isinstance(data, dict) else None
    value = task.get('result') if isinstance(task, dict) else None
    if not isinstance(value, dict) or task.get('status') != 'completed':
        return {**result, 'reason': '服务未完成检测'}
    if value.get('node_id') != node_id or value.get('host') != address or value.get('port') != port:
        return {**result, 'reason': '返回探测点、目标或端口不匹配'}
    rtt, size = value.get('rtt_ms'), value.get('response_bytes')
    if (type(rtt) not in (int, float) or not math.isfinite(rtt) or not 0 <= rtt <= 30000
            or type(size) is not int or not 0 <= size <= 65535):
        return {**result, 'reason': '返回耗时或字节数异常'}
    result.update(rtt_ms=rtt, response_bytes=size, task_id=task.get('task_id'))
    if value.get('responded') is True and value.get('success') is True and size > 0:
        return {**result, 'status': 'reply', 'reason': '国内UDP有回应；未返回原始回包，协议尚未核验'}
    if value.get('responded') is False and value.get('success') is False and size == 0:
        return {**result, 'status': 'no_reply', 'reason': '无回应不能直接判定国内不通'}
    return {**result, 'reason': '返回成功状态与字节数矛盾'}


class Provider:
    def __init__(self):
        self.client = s.session()
        self.pace = a.Pace(1)
        self.blocked = False
        self.units = 0
        self.token = ''

    def close(self):
        self.client.close()

    def request(self, method, path, **kwargs):
        if self.blocked or not self.pace.wait():
            raise ValueError('服务暂停检测')
        response = self.client.request(method, ORIGIN + path, timeout=(5, 10),
            headers={'X-CSRF-Token': self.token, 'Origin': ORIGIN, 'Referer': ORIGIN + '/tools/udp'}, **kwargs)
        if response.status_code in (401, 403, 429):
            self.blocked = True
        response.raise_for_status()
        return response

    def prepare(self):
        self.request('GET', '/tools/udp')
        self.token = self.client.cookies.get('csrf_token', '')
        return choose_probes(self.request('GET', '/v1/nodes').json())

    def probe(self, address, port, packet, probes):
        unknown = [{'status': 'unknown', 'probe_id': n['id'], 'protocol_verified': False,
                    'reason': '服务不可用、预算用完或响应异常'} for n in probes]
        if self.blocked or self.units + len(probes) > MAX_UNITS or not probes:
            return unknown
        self.units += len(probes)
        host = '[' + address + ']' if ':' in address else address
        try:
            response = self.request('POST', '/v1/probe/udp', json={
                'target': host + ':' + str(port), 'node_ids': [n['id'] for n in probes],
                'params': {'payload': packet.hex(), 'timeout_ms': 5000}}).json()
            accepted = response.get('data', {})
            tasks = accepted.get('tasks', [])
            mapping = {t['node_id']: t['task_id'] for t in tasks if isinstance(t, dict)
                       and t.get('node_id') in {n['id'] for n in probes}
                       and isinstance(t.get('task_id'), str) and t['task_id'].startswith('pt_')
                       and t['task_id'].replace('_', '').isalnum()}
            result = []
            for fallback in unknown:
                tid = mapping.get(fallback['probe_id'])
                if not tid:
                    result.append(fallback); continue
                data = {}
                for _ in range(12):
                    data = self.request('GET', '/v1/probe/tasks/' + tid).json()
                    if data.get('data', {}).get('status') not in ('queued', 'running'):
                        break
                    time.sleep(1)
                if data.get('data', {}).get('task_id') != tid:
                    result.append(fallback)
                else:
                    result.append(parse_result(data, fallback['probe_id'], address, port))
            return result
        except (s.requests.RequestException, ValueError, TypeError, KeyError, AttributeError):
            return unknown


def run_diagnostic(binary, root, bundle, report):
    nodes = choose_samples(bundle['nodes'], report['nodes'])
    rows = [{'id': n['name'], 'obfuscation': n.get('obfs') or 'none',
             'domestic_entry_status': 'unknown', 'domestic_rounds': []} for n in nodes]
    if nodes:
        listeners, ports = s.make_listeners(rows)
        cloud_root = root / 'cloud'; cloud_root.mkdir(parents=True, exist_ok=True)
        with s.Core(binary, cloud_root, nodes, listeners), futures.ThreadPoolExecutor(max_workers=4) as pool:
            prechecks = list(pool.map(lambda row: a.precheck_204(ports[row['id']]), rows))
        for row, pre in zip(rows, prechecks):
            row['cloud_204'] = pre
    active = [n for n, row in zip(nodes, rows) if row['cloud_204']['status'] == 'passed']
    provider = Provider()
    result = {'scope': 'diagnostic_only_no_subscription_change',
        'updated_at': s.datetime.now(s.TZ).isoformat(timespec='seconds'),
        'source_report_updated_at': report['updated_at'], 'provider': 'idcd',
        'max_probe_units': MAX_UNITS, 'raw_response_available': False,
        'production_gate_ready': False, 'probes': [], 'control': [], 'nodes': rows}
    try:
        probes = provider.prepare(); result['probes'] = probes
        result['control'] = provider.probe('223.5.5.5', 53, DNS_PAYLOAD, probes)
        working = {item['probe_id'] for item in result['control'] if item['status'] == 'reply'}
        probes = [n for n in probes if n['id'] in working]
        # Source addresses differ between probes. Each needs a fresh QUIC connection ID.
        # Use one extra fresh Initial for the independent GitHub UDP control.
        packets = capture_initials(binary, root / 'capture', active, rounds=3 * len(probes) + 1) if probes else {}
        for node, row in zip(nodes, rows):
            if row['cloud_204']['status'] != 'passed':
                row['reason'] = '当前云端204未三轮通过，跳过国内探测'; continue
            try:
                address = public_address(node['server']); port = int(node['port'])
                row['version_probe'] = provider.probe(address, port, version_packet(node), probes)
                cloud_packet = packets.get(node['name'] + '-initial-' + str(3 * len(probes)))
                if cloud_packet:
                    row['cloud_udp_control'] = cloud_udp(address, port, cloud_packet, node)
                for index in range(3):
                    measurements, sizes = [], []
                    for probe_index, probe in enumerate(probes):
                        packet = packets.get(node['name'] + '-initial-' + str(index * len(probes) + probe_index))
                        if not packet:
                            measurements.append({'status': 'unknown', 'probe_id': probe['id'],
                                'reason': '未生成可识别的原生QUIC初始包'}); continue
                        sizes.append(len(packet))
                        measurements.extend(provider.probe(address, port, packet, [probe]))
                    row['domestic_rounds'].append({'round': index + 1,
                        'payload_kind': 'mihomo_native_quic_initial_unique_per_probe', 'payload_bytes': sizes,
                        'probes': measurements})
                row['domestic_udp_three_rounds_replied'] = bool(probes) and len(row['domestic_rounds']) == 3 and all(
                    len(x.get('probes', [])) == len(probes)
                    and all(y['status'] == 'reply' for y in x['probes']) for x in row['domestic_rounds'])
            except (OSError, ValueError, TypeError, KeyError):
                row['reason'] = '公网入口或探测参数无法确认'
            print('HY2国内探测完成：' + row['id'], flush=True)
    except (s.requests.RequestException, ValueError, TypeError, KeyError, AttributeError):
        result['provider_status'] = 'unknown'
    finally:
        result['probe_units_submitted'] = provider.units
        result['provider_blocked'] = provider.blocked
        provider.close()
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    root = Path('.node-work/hysteria2-diagnostics').resolve(); root.mkdir(parents=True, exist_ok=True)
    result = run_diagnostic(str(Path(args.mihomo).resolve()), root,
        json.loads(Path(args.bundle).read_text()), json.loads(Path(args.report).read_text()))
    (root / 'summary.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    lines = ['# Hysteria2 国内UDP与云端认证诊断', '',
        '只读小样本，不修改订阅。无回应为未知；有回应未验证原始QUIC回包。', '',
        '|样本|混淆|云端204三轮|国内原生初始包三轮均有回应|国内入口分类|', '|---|---|---|---|---|']
    for row in result['nodes']:
        lines.append('|' + '|'.join((row['id'], row['obfuscation'], row['cloud_204']['status'],
            str(row.get('domestic_udp_three_rounds_replied', False)), row['domestic_entry_status'])) + '|')
    lines += ['', '探测点：' + '、'.join(n['name'] for n in result['probes']),
              '提交的探测点任务：' + str(result['probe_units_submitted']) + '/' + str(MAX_UNITS),
              '服务暂停：' + str(result['provider_blocked']),
              '完整响应及各轮延迟见同一附件的 summary.json；未上传载荷、节点配置或密钥。']
    (root / 'summary.md').write_text('\n'.join(lines) + '\n')
    print('\n'.join(lines), flush=True)


if __name__ == '__main__':
    main()
