"""Supplementary service requests; only certificate failures affect selection."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
import json
import re
import statistics
import time
from urllib.parse import urljoin, urlparse, urlunparse

import select_nodes as s
from mobile_pilot import WEB_USER_AGENT, certificate_failure

VERSION = 3
CHATGPT_API = 'https://api.openai.com/compliance/cookie_requirements'
# Public browser token from FAST, not an account credential. Never publish its query.
FAST_API = ('https://api.fast.com/netflix/speedtest/v2?https=true&'
            'token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=3')
FAST_TARGET_COUNT = 3
TARGETS = ('ChatGPTAPI', 'FAST')
API_BUDGET = 5
BODY_LIMIT = 65536
DOWNLOAD_BYTES = 1_000_000
DOWNLOAD_BUDGET = 6


def settings():
    return {'version': VERSION, 'scope': 'after_passed_1MB_download',
        'targets': {'FAST': public_url(FAST_API)},
        'api_budget_seconds': API_BUDGET, 'api_body_limit_bytes': BODY_LIMIT,
        'fast_download_bytes': DOWNLOAD_BYTES, 'fast_download_budget_seconds': DOWNLOAD_BUDGET,
        'fast_target_count': FAST_TARGET_COUNT, 'fast_target_order': 'sequential_distinct_hosts',
        'parallel_targets': 1, 'tls_verification': True, 'affects_selection': 'certificate_errors_only',
        'counts_as_website_coverage': False, 'replaces_existing_download_tests': False}


def public_url(url):
    parsed = urlparse(url)
    return f'{parsed.scheme}://{parsed.hostname or ""}{parsed.path}'


def fetch(port, url):
    """Bounded response with strict TLS; raw bytes stay inside this module."""
    started = time.monotonic()
    result = {'status': 'failed', 'url': public_url(url), 'budget_seconds': API_BUDGET}
    with s.session() as client:
        if port is not None:
            client.proxies = {k: f'http://127.0.0.1:{port}' for k in ('http', 'https')}
        try:
            with client.get(url, stream=True, verify=True, allow_redirects=False, timeout=(2, 1),
                            headers={'User-Agent': WEB_USER_AGENT, 'Accept-Encoding': 'identity'}) as response:
                result.update(http_status=response.status_code,
                    ttfb_ms=round((time.monotonic() - started) * 1000, 1),
                    final_url=public_url(response.url),
                    content_type=response.headers.get('Content-Type', '')[:160])
                body = bytearray()
                for chunk in response.iter_content(2048):
                    body.extend(chunk[:BODY_LIMIT + 1 - len(body)])
                    if len(body) > BODY_LIMIT or time.monotonic() - started > API_BUDGET:
                        break
                result.update(elapsed_ms=round((time.monotonic() - started) * 1000, 1), sample_bytes=len(body))
                if len(body) > BODY_LIMIT or result['elapsed_ms'] > API_BUDGET * 1000:
                    result['reason'] = '接口响应超过正文或时间预算'
                elif response.url != url or 300 <= response.status_code < 400:
                    result.update(status='restricted', reason='接口发生跳转，未确认预期响应')
                    if response.headers.get('Location'):
                        result['redirect_target'] = public_url(urljoin(url, response.headers['Location']))
                elif response.headers.get('cf-mitigated', '').strip().lower() == 'challenge':
                    result.update(status='verification_required', reason='明确CF人机验证，认可可达；接口内容未验证')
                elif response.status_code in (401, 403, 429, 451):
                    result.update(status='restricted', reason='接口鉴权、访问或速率限制')
                elif response.status_code == 404:
                    result.update(status='unavailable', reason='检测接口返回404，不能据此判断节点失效')
                elif response.status_code != 200:
                    result.update(status='unknown', reason='接口未返回预期状态')
                else:
                    result.update(status='response_received', reason='等待内容校验')
                return result, bytes(body)
        except (s.requests.RequestException, OSError) as error:
            result.update(reason='接口连接、TLS或读取失败', error_type=type(error).__name__,
                          elapsed_ms=round((time.monotonic() - started) * 1000, 1))
            if certificate_failure(error):
                result['tls_error_kind'] = 'certificate_verification_failed'
            return result, b''


def chatgpt_api(port):
    result, body = fetch(port, CHATGPT_API)
    try:
        data = json.loads(body)
    except (ValueError, UnicodeError):
        data = None
    # Explicit API errors are evidence; absence of this error is never enough.
    error = data.get('error') if isinstance(data, dict) else None
    code = error.get('code') if isinstance(error, dict) else None
    if code in ('unsupported_country', 'unsupported_country_region_territory') and result['status'] in ('response_received', 'restricted'):
        return {**result, 'status': 'restricted', 'restriction': 'unsupported_country',
                'reason': 'API明确返回地区不支持'}
    if result['status'] != 'response_received':
        return result
    if ('json' in result.get('content_type', '').lower() and isinstance(data, dict)
            and type(data.get('cookie_consent_required')) is bool and not data.get('error')):
        return {**result, 'status': 'passed', 'cookie_consent_required': data['cookie_consent_required'],
                'reason': 'API返回预期JSON；已验证接口请求，未验证登录或对话'}
    return {**result, 'status': 'unknown', 'reason': 'API响应格式或预期字段不匹配'}


def fast_targets(data):
    """Allow only HTTPS Netflix CDN range URLs; never arbitrary API-supplied hosts."""
    targets = data if isinstance(data, list) else data.get('targets') if isinstance(data, dict) else None
    if not isinstance(targets, list):
        return []
    selected, hosts = [], set()
    for target in targets:
        if not isinstance(target, dict) or not isinstance(target.get('url'), str):
            continue
        try:
            parsed = urlparse(target['url'])
            valid = (parsed.scheme == 'https' and parsed.hostname is not None
                and parsed.hostname.endswith('.nflxvideo.net') and parsed.port in (None, 443)
                and not parsed.username and not parsed.password and not parsed.fragment
                and re.fullmatch(r'/speedtest(?:/range/0-\d+)?', parsed.path))
        except ValueError:
            valid = False
        if valid and parsed.hostname not in hosts:
            location = target.get('location') or {}
            cc = location.get('country') if isinstance(location, dict) else None
            selected.append((urlunparse(parsed._replace(path=f'/speedtest/range/0-{DOWNLOAD_BYTES - 1}')),
                             cc if isinstance(cc, str) and re.fullmatch('[A-Z]{2}', cc) else None))
            hosts.add(parsed.hostname)
            if len(selected) == FAST_TARGET_COUNT:
                break
    return selected


def fast_target(data):
    """Compatibility helper for callers requesting a single validated target."""
    return next(iter(fast_targets(data)), None)


def aggregate_downloads(downloads):
    successful = [x for x in downloads if x.get('status') == 'passed']
    speeds = [x['speed_mbps'] for x in successful if isinstance(x.get('speed_mbps'), (int, float))]
    passed = len(downloads) == FAST_TARGET_COUNT and len(successful) == FAST_TARGET_COUNT
    result = {'status': 'passed' if passed else 'failed' if len(downloads) == FAST_TARGET_COUNT else 'unknown',
        'requested_target_count': FAST_TARGET_COUNT, 'measured_target_count': len(downloads),
        'passed_target_count': len(successful), 'budget_seconds_per_target': DOWNLOAD_BUDGET,
        'requested_bytes_per_target': DOWNLOAD_BYTES,
        'received_bytes': sum(x.get('received_bytes', 0) for x in downloads),
        'speed_mbps': round(statistics.median(speeds), 2) if speeds else None,
        'min_speed_mbps': min(speeds) if speeds else None,
        'max_speed_mbps': max(speeds) if speeds else None,
        'reason': f'Netflix CDN通过{len(successful)}/{FAST_TARGET_COUNT}个；每个1MB、6秒，速度为成功样本中位数'}
    if any(x.get('tls_error_kind') == 'certificate_verification_failed' for x in downloads):
        result['tls_error_kind'] = 'certificate_verification_failed'
    return result


def fast_download(port, url):
    started = time.monotonic()
    result = {'status': 'failed', 'cdn_host': urlparse(url).hostname,
              'requested_bytes': DOWNLOAD_BYTES, 'budget_seconds': DOWNLOAD_BUDGET,
              'received_bytes': 0, 'speed_mbps': None}
    with s.session() as client:
        if port is not None:
            client.proxies = {k: f'http://127.0.0.1:{port}' for k in ('http', 'https')}
        try:
            with client.get(url, stream=True, verify=True, allow_redirects=False, timeout=(2, 1),
                    headers={'User-Agent': WEB_USER_AGENT, 'Accept-Encoding': 'identity',
                             'Cache-Control': 'no-cache', 'Referer': 'https://fast.com/'}) as response:
                result.update(http_status=response.status_code,
                    ttfb_ms=round((time.monotonic() - started) * 1000, 1),
                    response_length=response.headers.get('Content-Length'),
                    content_type=response.headers.get('Content-Type', '')[:160])
                if (response.status_code != 200 or response.url != url
                        or response.headers.get('Content-Length') != str(DOWNLOAD_BYTES)
                        or response.headers.get('Content-Type', '').split(';')[0].lower() not in ('application/octet-stream', 'binary/octet-stream')
                        or response.headers.get('Content-Encoding', 'identity') != 'identity'):
                    result['reason'] = 'Netflix CDN未返回预期完整测速文件'
                else:
                    received = 0
                    while received <= DOWNLOAD_BYTES and time.monotonic() - started < DOWNLOAD_BUDGET:
                        chunk = response.raw.read1(min(16384, DOWNLOAD_BYTES + 1 - received))
                        if not chunk:
                            break
                        received += len(chunk)
                        result['received_bytes'] = received
                    elapsed = time.monotonic() - started
                    result.update(received_bytes=received, elapsed_ms=round(elapsed * 1000, 1))
                    if received == DOWNLOAD_BYTES and elapsed <= DOWNLOAD_BUDGET:
                        result.update(status='passed', speed_mbps=round(received * 8 / max(elapsed, .0001) / 1e6, 2),
                                      reason='Netflix CDN完整1MB下载；速度含建连，未验证内容解锁')
                    else:
                        result['reason'] = 'Netflix CDN未在6秒内完整下载1MB'
        except (s.requests.RequestException, OSError, s.requests.packages.urllib3.exceptions.HTTPError) as error:
            result.update(reason='Netflix CDN连接、TLS或读取失败', error_type=type(error).__name__)
            if certificate_failure(error):
                result['tls_error_kind'] = 'certificate_verification_failed'
        result.setdefault('elapsed_ms', round((time.monotonic() - started) * 1000, 1))
        return result


def fast(port, download_gate=None):
    api, body = fetch(port, FAST_API)
    result = {'status': api['status'], 'api': api, 'reason': api['reason']}
    if api['status'] != 'response_received':
        return result
    try:
        data = json.loads(body) if 'json' in api.get('content_type', '').lower() else None
        targets = data if isinstance(data, list) else data.get('targets') if isinstance(data, dict) else None
        selected = fast_targets(data)
        api['target_shape'] = {'payload_type': type(data).__name__,
            'target_count': len(targets) if isinstance(targets, list) else None,
            'url_shapes': [public_url(url) for url, _ in selected]}
    except (ValueError, UnicodeError):
        selected = []
    if not selected:
        api.update(status='unknown', reason='FAST API未返回可信测速目标')
        return {**result, 'status': 'unknown', 'reason': api['reason']}
    api.update(status='passed', reason='FAST API返回有效Netflix CDN测速目标',
               selected_target_count=len(selected))
    downloads = []
    for url, cc in selected:
        with download_gate.download() if download_gate is not None else nullcontext():
            downloads.append({**fast_download(port, url), 'cdn_country_code': cc})
    downloaded = aggregate_downloads(downloads)
    return {**result, 'status': downloaded['status'], 'reason': downloaded['reason'],
            'downloads': downloads, 'download': downloaded}


def check(port, download_gate=None):
    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = {'ChatGPTAPI': pool.submit(chatgpt_api, port), 'FAST': pool.submit(fast, port, download_gate)}
        return {'version': VERSION, 'updated_at': s.datetime.now(s.TZ).isoformat(timespec='seconds'),
                'targets': {name: job.result() for name, job in jobs.items()}}


def check_fast(port, download_gate=None):
    return {'version': VERSION, 'updated_at': s.datetime.now(s.TZ).isoformat(timespec='seconds'),
            'targets': {'FAST': fast(port, download_gate)}}


def certificate_errors(checks):
    result = []
    for label, item in (checks or {}).get('targets', {}).items():
        if any(x.get('tls_error_kind') == 'certificate_verification_failed'
               for x in (item, item.get('api') or {}, item.get('download') or {}, *item.get('downloads', []))):
            result.append(label)
    return result


def complete(checks):
    if not isinstance(checks, dict) or checks.get('version') != VERSION:
        return False
    targets = checks.get('targets')
    basic = (isinstance(targets, dict) and set(targets) in (set(TARGETS), {'FAST'})
        and all(isinstance(x, dict) and x.get('status') in
                ('passed', 'restricted', 'verification_required', 'unavailable', 'unknown', 'failed')
                for x in targets.values()))
    if not basic:
        return False
    fast_result = targets['FAST']
    if (fast_result.get('api') or {}).get('status') != 'passed':
        return True
    downloads = fast_result.get('downloads')
    if (not isinstance(downloads, list) or not 1 <= len(downloads) <= FAST_TARGET_COUNT
            or any(not isinstance(x, dict) or x.get('status') not in ('passed', 'failed') for x in downloads)
            or any(not isinstance(x.get('cdn_host'), str) for x in downloads)
            or len({x['cdn_host'] for x in downloads}) != len(downloads)):
        return False
    aggregated = aggregate_downloads(downloads)
    return (fast_result['api'].get('selected_target_count') == len(downloads)
            and fast_result.get('download') == aggregated and fast_result.get('status') == aggregated['status'])


def summary(nodes):
    result = {}
    for label in (*TARGETS, 'FASTAPI'):
        counts = {k: 0 for k in ('measured', 'passed', 'restricted', 'verification_required',
                                'unavailable', 'unknown', 'failed', 'unmeasured', 'certificate_error')}
        for row in nodes:
            checks = row.get('service_checks') or {}
            item = checks.get('targets', {}).get('FAST' if label == 'FASTAPI' else label) or {}
            if label == 'FASTAPI':
                item = item.get('api') or {}
            elif label == 'FAST':
                item = item.get('download') or {}
            status = item.get('status')
            if status not in counts or status in ('unmeasured', 'measured', 'certificate_error'):
                counts['unmeasured'] += 1
                continue
            counts['measured'] += 1
            counts[status] += 1
            counts['certificate_error'] += item.get('tls_error_kind') == 'certificate_verification_failed'
        result[label] = counts
    return result


def cdn_summary(nodes):
    """Count actual target downloads, including historical single-target records."""
    counts = {'measured': 0, 'passed': 0, 'failed': 0, 'certificate_error': 0}
    for row in nodes:
        item = (row.get('service_checks') or {}).get('targets', {}).get('FAST') or {}
        for sample in item.get('downloads', [item['download']] if item.get('download') else []):
            counts['measured'] += 1
            counts['passed'] += sample.get('status') == 'passed'
            counts['failed'] += sample.get('status') != 'passed'
            counts['certificate_error'] += sample.get('tls_error_kind') == 'certificate_verification_failed'
    return counts
