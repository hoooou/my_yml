"""Bounded HTTPS upload samples; synthetic payloads, never user files.

HTTP completion is the same level of evidence used by the public speedtest
engine. It is not a byte-by-byte receipt or a measurement of China's uplink.
"""
import concurrent.futures as futures
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import tempfile
import time

import certifi
import select_nodes as s
from mobile_pilot import check_site, SITES

VERSION = 1
BYTES = 5_000_000
PRECHECK_BYTES = 1_000_000
PRECHECK_BUDGET = 6
BUDGET = 10
ROUNDS = 2
GAP_SECONDS = 20
WORKERS = 4


def url(byte_count):
    return f'https://speed.cloudflare.com/__up?bytes={byte_count}'


def settings():
    return {'version': VERSION, 'url': url(BYTES), 'bytes_per_round': BYTES,
            'rounds': ROUNDS, 'budget_seconds_per_round': BUDGET,
            'precheck_bytes': PRECHECK_BYTES, 'precheck_budget_seconds': PRECHECK_BUDGET,
            'minimum_idle_seconds_between_rounds': GAP_SECONDS, 'workers': WORKERS,
            'payload': 'random_synthetic_bytes', 'strict_destination_tls': True,
            'redirects_allowed': False, 'includes_handshake': True,
            'speed_aggregation': 'minimum_of_completed_rounds',
            'server_byte_receipt_available': False, 'china_mobile_uplink_measured': False}


def finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def sample_passed(item, byte_count=BYTES, budget=BUDGET):
    elapsed, speed = item.get('elapsed_ms'), item.get('speed_mbps')
    return (item.get('version') == VERSION and item.get('status') == 'passed'
            and item.get('url') == item.get('effective_url') == url(byte_count)
            and item.get('requested_bytes') == item.get('uploaded_bytes') == byte_count
            and item.get('budget_seconds') == budget and item.get('curl_exit_code') == 0
            and item.get('http_status') == 200 and item.get('redirect_count') == 0
            and item.get('ssl_verify_result') == 0 and item.get('tls_verification_enabled') is True
            and item.get('http_completed') is True
            and finite(elapsed) and 0 < elapsed <= budget * 1000
            and finite(speed) and speed > 0
            and abs(speed - byte_count * 8 / (elapsed / 1000) / 1_000_000) <= .01)


def sample(port, byte_count=BYTES, budget=BUDGET, directory=None):
    """curl's total deadline covers write stalls as well as connection/read."""
    result = {'version': VERSION, 'status': 'failed', 'url': url(byte_count),
              'requested_bytes': byte_count, 'budget_seconds': budget,
              'tls_verification_enabled': True, 'http_completed': False}
    with tempfile.TemporaryDirectory(dir=directory) as folder:
        root = Path(folder)
        payload, body, headers = root / 'payload.bin', root / 'response', root / 'headers'
        payload.write_bytes(os.urandom(byte_count))
        command = ['curl', '--disable', '--silent', '--show-error', '--http1.1',
                   '--proto', '=https', '--connect-timeout', '2', '--max-time', str(budget),
                   '--cacert', certifi.where(), '--noproxy', '',
                   '--proxy', f'http://127.0.0.1:{port}' if port is not None else '',
                   '--header', 'Content-Type: application/octet-stream', '--header', 'Expect:',
                   '--header', 'Referer: https://speed.cloudflare.com/',
                   '--header', 'Accept-Encoding: identity', '--data-binary', '@' + str(payload),
                   '--max-filesize', '65536', '--output', str(body), '--dump-header', str(headers),
                   '--write-out', '%{json}', result['url']]
        try:
            process = subprocess.run(command, capture_output=True, text=True, timeout=budget + 3)
            info = json.loads(process.stdout)
            elapsed = max(round(info['time_total'] * 1000, 1), .1)
            result.update(curl_exit_code=process.returncode, http_status=info['http_code'],
                effective_url=info['url_effective'], uploaded_bytes=info['size_upload'],
                elapsed_ms=elapsed, ssl_verify_result=info['ssl_verify_result'],
                redirect_count=info['num_redirects'], http_completed=process.returncode == 0,
                speed_mbps=round(byte_count * 8 / (elapsed / 1000) / 1_000_000, 3))
            raw = body.read_bytes() if body.exists() else b''
            result.update(response_bytes=len(raw), response_sha256=hashlib.sha256(raw).hexdigest())
            if headers.exists():
                # Do not retain cookies, request headers or complete server payloads.
                allowed = ('content-type', 'server-timing', 'cf-meta-colo')
                result['response_headers'] = {line.split(':', 1)[0].lower(): line.split(':', 1)[1].strip()
                    for line in headers.read_text(errors='replace').splitlines()
                    if ':' in line and line.split(':', 1)[0].lower() in allowed}
            result['status'] = 'passed'
            if not sample_passed(result, byte_count, budget):
                result['status'] = 'failed'
            result['reason'] = ('完整HTTPS上传请求完成；无逐字节接收回执' if result['status'] == 'passed'
                else '上传未完整完成、响应异常、证书失败或超出预算')
            if process.returncode:
                result['error_type'] = {28: 'timeout', 60: 'certificate_verification_failed',
                    35: 'tls_handshake_failed'}.get(process.returncode, 'curl_connection_or_protocol_failed')
            return result
        except subprocess.TimeoutExpired:
            return {**result, 'error_type': 'process_deadline', 'reason': '上传进程超出总预算'}
        except (OSError, ValueError, KeyError, TypeError):
            return {**result, 'error_type': 'measurement_error', 'reason': '上传测量工具或数据异常'}


def loaded_sample(port, directory=None):
    # One upload plus sparse latency probes; never another bandwidth transfer.
    probes = []
    with futures.ThreadPoolExecutor(max_workers=1) as pool:
        job = pool.submit(sample, port, BYTES, BUDGET, directory)
        while not job.done():
            probe = check_site(port, 'Google204', SITES['Google204'], timeout=(2, 1))
            probes.append(probe)
            try:
                job.result(timeout=.5)
            except futures.TimeoutError:
                pass
        result = job.result()
    return {**result, 'loaded_204': probes}


def summarize(precheck, attempts, idle):
    complete = sample_passed(precheck, PRECHECK_BYTES, PRECHECK_BUDGET) and len(attempts) == ROUNDS
    complete = complete and finite(idle) and idle >= GAP_SECONDS and all(sample_passed(x) for x in attempts)
    speeds = [x['speed_mbps'] for x in attempts if sample_passed(x)]
    return {'version': VERSION, 'status': 'passed' if complete else 'failed',
            'precheck': precheck, 'attempts': attempts, 'idle_seconds': idle,
            'round_count': len(attempts), 'passed_count': sum(sample_passed(x) for x in attempts),
            'speed_mbps': min(speeds) if complete else None,
            'speed_ratio': min(speeds) / max(speeds) if len(speeds) == ROUNDS else None,
            'updated_at': s.datetime.now(s.TZ).isoformat(timespec='seconds')}


def passed(item):
    if not isinstance(item, dict) or item.get('version') != VERSION or item.get('status') != 'passed':
        return False
    derived = summarize(item.get('precheck') or {}, item.get('attempts') or [], item.get('idle_seconds'))
    return derived['status'] == 'passed' and all(item.get(k) == derived[k]
        for k in ('round_count', 'passed_count', 'speed_mbps', 'speed_ratio'))


def check(port, directory=None):
    precheck = sample(port, PRECHECK_BYTES, PRECHECK_BUDGET, directory)
    if not sample_passed(precheck, PRECHECK_BYTES, PRECHECK_BUDGET):
        return summarize(precheck, [], None)
    first = loaded_sample(port, directory)
    ended = time.monotonic()
    time.sleep(GAP_SECONDS)
    idle = time.monotonic() - ended
    second = loaded_sample(port, directory)
    return summarize(precheck, [first, second], idle)


def recheck(records, mapping, binary, root):
    root = Path(root); root.mkdir(parents=True, exist_ok=True)
    if not records:
        return {'settings': settings(), 'node_count': 0, 'nodes': []}
    listeners, ports = s.make_listeners(records)
    with s.Core(binary, root, [mapping[r['id']] for r in records], listeners) as core:
        control_before = check(None, root)
        with futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
            jobs = {pool.submit(check, ports[r['id']], root): r for r in records}
            for job in futures.as_completed(jobs):
                row = jobs[job]; row['upload'] = job.result()
                print('上传复测完成 ' + row['id'] + '：' + row['upload']['status'], flush=True)
        control_after = check(None, root)
        import stability
        health = stability.core_health(core, root)
    diagnostic = {'updated_at': s.datetime.now(s.TZ).isoformat(timespec='seconds'),
        'settings': settings(), 'node_count': len(records), 'core_health': health,
        'controls': {'before': control_before, 'after': control_after},
        'controls_valid': passed(control_before) and passed(control_after) and stability.core_healthy(health),
        'nodes': [{'id': r['id'], 'upload': r['upload']} for r in records]}
    (root / 'upload-results.json').write_text(json.dumps(diagnostic, ensure_ascii=False, indent=2) + '\n')
    if not diagnostic['controls_valid']:
        raise RuntimeError('上传直连或内核对照异常，记录已保存；不据此淘汰或发布')
    return diagnostic
