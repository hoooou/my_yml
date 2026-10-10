#!/usr/bin/env python3
"""Small, repeatable China Mobile ingress and cloud application comparison."""
import argparse
import concurrent.futures as futures
import copy
import ipaddress
import json
import math
import re
from pathlib import Path
import statistics
import subprocess
import time
from urllib.parse import urlparse, urljoin

import yaml
import select_nodes as s
from site_catalog import PAGES, OVERSEAS, DOMESTIC

GLOBALPING = 'https://api.globalping.io/v1'
MOBILE_ASN = 9808
UDP_TYPES = {'hysteria', 'hysteria2', 'tuic', 'wireguard'}
# Keep Douyin's domain routing in the catalog, but do not probe it.
SITES = {label: item['url'] for label, item in PAGES.items() if label != '抖音'}
PAGE_SITES = tuple(SITES)
OVERSEAS_SITES = tuple(OVERSEAS)
DOMESTIC_SITES = tuple(label for label in DOMESTIC if label in SITES)
SITE_WORKERS = 5
WEB_USER_AGENT = 'my-yml-availability-bot/5.0 (https://github.com/hoooou/my_yml) python-requests/' + s.requests.__version__
MAX_TTFB_MS = 3000
MAX_SAMPLE_MS = 5000
PAGE_SAMPLE_BYTES = 16384
PAGE_MARKERS = {label: item['markers'] for label, item in PAGES.items()}
# Permit only the entry hostname and its explicit www/non-www counterpart.
PAGE_HOSTS = {}
for label in PAGE_SITES:
    host = urlparse(SITES[label]).hostname
    PAGE_HOSTS[label] = {host, host[4:] if host.startswith('www.') else 'www.' + host}
CONNECTIVITY_SITES = {
    'Google204': 'https://connectivitycheck.gstatic.com/generate_204',
    'ChatGPTTrace': 'https://chatgpt.com/cdn-cgi/trace',
    'ClaudeTrace': 'https://claude.ai/cdn-cgi/trace',
}
SITES.update(CONNECTIVITY_SITES)
POST_SITES = {label: url for label, url in SITES.items() if label != 'Google204'}


def parse_mobile_result(data, measurement_id):
    probes = []
    for item in data.get('results', []):
        probe, result = item.get('probe', {}), item.get('result', {})
        if probe.get('country') != 'CN' or probe.get('asn') != MOBILE_ASN:
            continue
        stats = result.get('stats', {})
        if result.get('status') != 'finished' or stats.get('total') != 3:
            continue
        received, loss, avg = stats.get('rcv'), stats.get('loss'), stats.get('avg')
        if (type(received) is not int or received not in range(4)
                or type(loss) not in (int, float) or not math.isfinite(loss)
                or abs(loss - (3 - received) * 100 / 3) > .5):
            continue
        if received and (type(avg) not in (float, int) or not math.isfinite(avg) or avg < 0):
            continue
        probes.append({'country': 'CN', 'asn': MOBILE_ASN, 'city': probe.get('city'),
                       'network': probe.get('network'), 'received': received, 'total': 3,
                       'loss_percent': loss, 'latency_ms': avg, 'resolved_ip': result.get('resolvedAddress')})
    outcome = 'unknown'
    if data.get('status') == 'finished' and len(probes) == 2:
        outcome = ('passed' if all(p['received'] == 3 for p in probes)
                   else 'failed' if all(p['received'] == 0 for p in probes) else 'unstable')
    delays = [p['latency_ms'] for p in probes if p['received']]
    return {'status': outcome, 'measurement_id': measurement_id,
            'measurement_url': 'https://globalping.io?measurement=' + measurement_id,
            'latency_ms': round(statistics.median(delays), 2) if delays else None,
            'probes': probes}


def check_mobile(node):
    if node['type'] in UDP_TYPES or node.get('network') == 'quic':
        return {'status': 'unknown', 'reason': 'UDP 协议，TCP 入口探测不适用'}
    try:
        try:
            address = ipaddress.ip_address(node['server'])
            if not address.is_global:
                return {'status': 'unknown', 'reason': '非公网入口不提交第三方探测'}
        except ValueError:
            pass
        with s.session() as client:
            payload = {'type': 'ping', 'target': node['server'], 'limit': 2,
                       'locations': [{'country': 'CN', 'asn': MOBILE_ASN, 'tags': ['eyeball-network']}],
                       'measurementOptions': {'protocol': 'TCP', 'port': int(node['port']), 'packets': 3}}
            response = client.post(GLOBALPING + '/measurements', json=payload, timeout=12)
            if response.status_code == 429:
                return {'status': 'unknown', 'reason': '国内探测免费配额不足'}
            response.raise_for_status()
            info = response.json()
            if response.status_code != 202 or info.get('probesCount') != 2:
                return {'status': 'unknown', 'reason': '未分配到两个移动探测点'}
            measurement_id = info['id']
            deadline = time.monotonic() + 50
            while time.monotonic() < deadline:
                time.sleep(1)
                result = client.get(GLOBALPING + '/measurements/' + measurement_id, timeout=12)
                result.raise_for_status()
                data = result.json()
                if data.get('status') != 'in-progress':
                    return parse_mobile_result(data, measurement_id)
            return {'status': 'unknown', 'reason': '国内探测结果超时', 'measurement_id': measurement_id}
    except (s.requests.RequestException, ValueError, KeyError, TypeError):
        return {'status': 'unknown', 'reason': '国内探测服务未返回可靠结果'}


def classify_page(label, status, final_url, content_type, body):
    result = {'http_status': status, 'final_url': final_url}
    text = body.decode('utf-8', errors='replace').lower()
    host = urlparse(final_url).hostname or ''
    expected_host = urlparse(SITES[label]).hostname
    # Normal pages can mention captcha in feature flags or scripts (e.g. GitHub).
    visible = re.sub(r'<(?:script|style)\b[^>]*>.*?(?:</(?:script|style)>|$)', '', text, flags=re.S)
    title = re.search(r'<title\b[^>]*>(.*?)</title>', visible, flags=re.S)
    captcha_wall = (title is not None and 'captcha' in title[1]) or bool(
        re.search(r'(?:class|id)=["\'][^"\']*(?:g-recaptcha|h-captcha)', visible))
    if captcha_wall or any(word in text for word in ('cf-chl-', 'just a moment', 'verify you are human',
                                                     'unsupported_country', 'unsupported country')):
        return {**result, 'status': 'needs_review', 'reason': '登录、风控、验证码或地区限制，无法自动确认服务可用'}
    allowed_hosts = PAGE_HOSTS.get(label, {expected_host})
    if status in (401, 403, 412, 418, 429, 444, 451) or 300 <= status < 400 or host not in allowed_hosts or urlparse(final_url).scheme != 'https':
        return {**result, 'status': 'needs_review', 'reason': '需人工确认登录、访问限制或跳转'}
    if label in CONNECTIVITY_SITES:
        if final_url != SITES[label]:
            return {**result, 'status': 'needs_review', 'reason': '检测地址发生跳转'}
        if label == 'Google204':
            passed = status == 204 and not body
            return {**result, 'status': 'passed' if passed else 'failed',
                    'reason': 'HTTPS 204 连通正常' if passed else '未返回无正文的 204'}
        fields = dict(line.split('=', 1) for line in body.decode('utf-8', errors='replace').splitlines() if '=' in line)
        try:
            valid_ip = ipaddress.ip_address(fields.get('ip', '')).is_global
        except ValueError:
            valid_ip = False
        passed = (status == 200 and 'text/plain' in content_type.lower() and valid_ip
                  and fields.get('h') == expected_host and fields.get('visit_scheme') == 'https'
                  and len(fields.get('loc', '')) == 2 and fields['loc'].isascii()
                  and fields['loc'].isalpha() and fields['loc'].isupper())
        return {**result, 'status': 'passed' if passed else 'failed',
                'reason': '域名 HTTPS 连通正常；未验证登录或对话' if passed else '未返回预期 Cloudflare trace',
                **({'exit_ip': fields['ip'], 'country_code': fields['loc'], 'colo': fields.get('colo')} if passed else {})}
    passed = status == 200 and 'html' in content_type.lower() and any(word in text for word in PAGE_MARKERS[label])
    return {**result, 'status': 'passed' if passed else 'failed',
            'reason': '网页入口正常；实际功能仍需本地测试' if passed else '未返回预期网页'}


def check_site(port, label, url, timeout=(3, 2)):
    with s.session() as client:
        client.proxies = {'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'}
        try:
            started = time.perf_counter()
            current_url = url
            for hop in range(3):
                with client.get(current_url, stream=True, timeout=timeout, allow_redirects=False,
                                headers={'User-Agent': WEB_USER_AGENT}) as response:
                    location = response.headers.get('Location')
                    if label in PAGE_SITES and 300 <= response.status_code < 400 and location:
                        target = urljoin(current_url, location)
                        # Follow up to two HTTPS redirects on the same website only.
                        if hop < 2 and urlparse(target).scheme == 'https' and urlparse(target).hostname in PAGE_HOSTS[label]:
                            current_url = target
                            continue
                    # Headers include DNS, handshake, redirects and server wait.
                    headers_ms = round((time.perf_counter() - started) * 1000, 1)
                    body = bytearray()
                    for chunk in response.iter_content(1024):
                        body.extend(chunk[:PAGE_SAMPLE_BYTES - len(body)])
                        if len(body) >= PAGE_SAMPLE_BYTES or (time.perf_counter() - started) * 1000 >= MAX_SAMPLE_MS:
                            break
                    result = classify_page(label, response.status_code, response.url,
                                           response.headers.get('Content-Type', ''), bytes(body))
                    result['elapsed_ms'] = round((time.perf_counter() - started) * 1000, 1)
                    result['ttfb_ms'] = headers_ms
                    result['sample_bytes'] = len(body)
                    result['sample_limit_bytes'] = PAGE_SAMPLE_BYTES
                    if label in PAGE_SITES and result['status'] == 'passed' and (
                            headers_ms > MAX_TTFB_MS or result['elapsed_ms'] > MAX_SAMPLE_MS):
                        result.update(status='slow', reason='HTTP 和网页特征正常，但请求响应超过速度预算')
                    result['redirect_hops'] = hop
                    return result
        except s.requests.RequestException:
            return {'status': 'failed', 'reason': '连接、TLS 或读取失败',
                    'elapsed_ms': round((time.perf_counter() - started) * 1000, 1)}


def check_sites(port, targets=None):
    # Each target has its own Session; page checks and light probes overlap.
    targets = SITES if targets is None else targets
    with futures.ThreadPoolExecutor(max_workers=min(SITE_WORKERS, len(targets))) as pool:
        jobs = {label: pool.submit(check_site, port, label, url) for label, url in targets.items()}
        return {label: job.result() for label, job in jobs.items()}


def mobile_label(record):
    return {'passed': '移动入口通', 'failed': '移动入口不通', 'unstable': '移动入口不稳定',
            'unknown': '入口未验证'}[record['mobile']['status']]


def render_pilot(base, records, mapping):
    prepared = [{**r, 'country_code': (r.get('exit') or {}).get('country_code', r['source_country']),
                 'latency_ms': r.get('cloud_latency_ms') or 0,
                 'speed_mib_s': r.get('download', {}).get('speed_mib_s') or 0} for r in records]
    non_dc = [r['id'] for r in records if r.get('ip_type', {}).get('status') == 'success'
              and r['ip_type'].get('hosting') is False]
    config = s.render_config(base, prepared, mapping, non_datacenter_ids=non_dc)
    renames = {}
    for record, row, node in zip(records, prepared, config['proxies']):
        country = row['country_code']
        region = s.COUNTRIES.get(country, country)
        speed = f"{row['speed_mib_s']:.2f}MiB/s" if record['download']['status'] == 'passed' else '下载未通过'
        name = f"{record['id'][2:8]} | {region} | {mobile_label(record)} | {speed}"
        renames[node['name']] = name
        node['name'] = name
        record['name'] = name
    for group in config['proxy-groups']:
        group['proxies'] = [renames.get(name, name) for name in group['proxies']]
    candidates = sorted([r for r in records if r['mobile']['status'] == 'passed'
                         and r['download']['status'] == 'passed' and r['websites']['Google']['status'] == 'passed'],
                        key=lambda r: (r['mobile']['latency_ms'], -r['download']['speed_mib_s']))
    uncertain = [r['name'] for r in records if r['mobile']['status'] in ('unknown', 'unstable')]
    config['proxy-groups'][0]['proxies'] = ['📶 移动入口候选', '🧪 全部样本', '🔎 入口待验证',
                                          '♻️ 低延迟', '🏠 非机房 IP']
    config['proxy-groups'] += [
        {'name': '📶 移动入口候选', 'type': 'select', 'proxies': [r['name'] for r in candidates] or ['REJECT']},
        {'name': '🧪 全部样本', 'type': 'select', 'proxies': [r['name'] for r in records]},
        {'name': '🔎 入口待验证', 'type': 'select', 'proxies': uncertain or ['REJECT']},
    ]
    # A comparison subscription sends test traffic through the chosen sample.
    config['rules'] = ['MATCH,🚀 全局选择']
    config.pop('rule-providers', None)
    return config, [r['id'] for r in candidates]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--speedtest', required=True)
    parser.add_argument('--sample', default='scripts/fixtures/mobile-sample.yaml')
    parser.add_argument('--work-dir', default='.node-work/mobile-pilot')
    args = parser.parse_args()
    args.mihomo = str(Path(args.mihomo).resolve())
    args.speedtest = str(Path(args.speedtest).resolve())
    root = Path(args.work_dir).resolve(); root.mkdir(parents=True, exist_ok=True)
    document = yaml.safe_load(Path(args.sample).read_text())
    samples = document['samples']
    if not samples or len(samples) > 30 or len({r['id'] for r in samples}) != len(samples):
        raise ValueError('小测需要 1–30 个不同编号的样本')
    mapping = {r['id']: {**copy.deepcopy(r['node']), 'name': r['id']} for r in samples}
    base = yaml.safe_load(Path('聚合配置.yaml').read_text())
    with s.session() as client:
        _, fingerprint = s.download_file(client)
    print(f'默认 Google 测速文件 10 MB 采样校验成功，开始 {len(samples)} 个固定样本对照', flush=True)
    mobile = {}
    # Only host and port are submitted; subscriptions, credentials and keys are never sent.
    with futures.ThreadPoolExecutor(max_workers=4) as pool:
        jobs = {pool.submit(check_mobile, node): name for name, node in mapping.items()}
        for job in futures.as_completed(jobs):
            name = jobs[job]; mobile[name] = job.result()
            print(f'移动入口 {len(mobile)}/{len(samples)}：{name} {mobile[name]["status"]}', flush=True)
    listeners, ports = s.make_listeners(samples)
    records = []
    with s.Core(args.mihomo, root, list(mapping.values()), listeners) as core:
        def measure(sample):
            name = sample['id']; node = mapping[name]; port = ports[name]
            _, latency = core.latency(node)
            record = {'id': name, 'source_country': sample['source_country'], 'protocol': node['type'],
                      'mobile': mobile[name], 'cloud_latency_ms': latency,
                      'download': {'status': 'failed'}, 'exit': None}
            try:
                record['exit'] = s.query_exit(port, {'id': name, 'latency_ms': latency or 0})
            except (s.requests.RequestException, ValueError, KeyError):
                pass
            measured = s.measure_file(args.speedtest, root, node, 1000)
            if measured and record['exit']:
                try:
                    verified = s.verify_exit(port, {**record['exit'], **measured}, fingerprint)
                    record['download'] = {'status': 'passed', **measured,
                                          'verification_speed_mib_s': verified['verification_speed_mib_s'],
                                          'speed_mib_s': verified['speed_mib_s']}
                except (s.requests.RequestException, ValueError, KeyError):
                    record['download']['reason'] = '采样内容、出口稳定性或最低速度未通过复测'
            record['websites'] = check_sites(port)
            return record
        with futures.ThreadPoolExecutor(max_workers=4) as pool:
            for record in pool.map(measure, samples):
                records.append(record)
                print(f'云端对照 {len(records)}/{len(samples)}：{record["id"]} 下载 {record["download"]["status"]}', flush=True)
    ip_types = s.lookup_ip_types(r['exit']['exit_ip'] for r in records if r['exit'])
    for record in records:
        record['ip_type'] = ip_types.get((record['exit'] or {}).get('exit_ip'), {'status': 'unknown', 'hosting': None})
    config, candidates = render_pilot(base, records, mapping)
    candidate = root / 'pilot-config.yaml'; s.dump(candidate, config)
    checked = subprocess.run([args.mihomo, '-t', '-d', str(root), '-f', str(candidate)],
                             capture_output=True, text=True, timeout=90)
    if checked.returncode:
        raise RuntimeError('测试订阅内核校验失败，不发布')
    now = s.datetime.now(s.TZ).isoformat(timespec='seconds')
    report = {'updated_at': now, 'kind': '中国移动 20 节点对照小测', 'sample_source_at': document['source_updated_at'],
              'download_url': s.DOWNLOAD_URL, 'sample_bytes': s.FILE_BYTES, 'sample_sha256': fingerprint,
              'sample_count': len(records), 'mobile_passed': sum(r['mobile']['status'] == 'passed' for r in records),
              'download_passed': sum(r['download']['status'] == 'passed' for r in records),
              'candidate_ids': candidates, 'nodes': records}
    Path('优选配置.yaml').write_text(f'# 移动网络对照小测；{now}；{len(records)} 个样本\n' + candidate.read_text())
    Path('移动小测报告.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    labels = {'passed': '通过', 'failed': '未通过', 'unknown': '未验证', 'unstable': '不稳定', 'needs_review': '需人工复核'}
    rows = ['# 中国移动小规模对照报告', '', f'更新时间：{now}', '',
            f'{len(records)} 个固定样本；移动 TCP 入口通过 {report["mobile_passed"]} 个，云端下载通过 {report["download_passed"]} 个，入口候选 {len(candidates)} 个。', '',
            f'下载地址：[{s.DOWNLOAD_URL}]({s.DOWNLOAD_URL})，每次采样 10 MB，工具测速后再校验完整采样内容。', '',
            '入口通过表示两个中国境内 AS9808 移动探测点各 3 次 TCP 连接全部成功。UDP 协议不套用 TCP 判定；服务异常、限流或探测点不足记为未验证。', '',
            'Google、YouTube、ChatGPT 只检查云端网页入口。网页通过不代表视频能播放或 ChatGPT 能登录、对话；验证码、403 和风控记为需人工复核。', '',
            '本次固定样本用于手机与云端对照，不代表已重新拉取全部来源，也不保证全国移动网络可用。', '',
            '## 手机测试', '', '刷新原订阅。在“🚀 全局选择”选择“📶 移动入口候选”；在该组逐个选节点。也可选“🧪 全部样本”对照入口失败和未验证节点。', '',
            '这份测试订阅的全部流量经过所选样本。请记录节点编号、本地延迟、Google 打开情况、YouTube 播放情况、ChatGPT 实际对话情况和下载速度。', '',
            '| 编号 | 来源地区 | 协议 | 移动入口 | 移动延迟 ms | 云端下载 MiB/s | Google | YouTube | ChatGPT |',
            '|---|---|---|---|---:|---:|---|---|---|']
    for record in records:
        rows.append(f"| {record['id'][2:8]} | {s.COUNTRIES.get(record['source_country'], record['source_country'])} | {record['protocol']} | "
                    f"{labels[record['mobile']['status']]} | {record['mobile'].get('latency_ms') or '—'} | "
                    f"{record['download'].get('speed_mib_s', '—')} | " +
                    ' | '.join(labels[record['websites'][site]['status']] for site in SITES) + ' |')
    rows += ['', '## 国内探测证据', '']
    for record in records:
        if record['mobile'].get('measurement_url'):
            rows.append(f"- [{record['id'][2:8]}]({record['mobile']['measurement_url']})")
    Path('移动小测报告.md').write_text('\n'.join(rows) + '\n')
    print(f'小测完成：{len(records)} 个样本，{len(candidates)} 个移动入口候选；订阅内核校验通过', flush=True)


if __name__ == '__main__':
    main()
