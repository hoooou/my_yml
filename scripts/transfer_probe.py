"""Complete downloads with one wall-clock deadline, strict TLS and bounded disk."""
import json
from pathlib import Path
import subprocess
import tempfile
import certifi
import high_speed
from mobile_pilot import WEB_USER_AGENT


def download(port, byte_count, budget, url=None):
    url = url or f'https://speed.cloudflare.com/__down?bytes={byte_count}'
    headers = {**high_speed.request_headers(url), 'Accept-Encoding': 'identity',
               'Cache-Control': 'no-cache', 'Referer': 'https://speed.cloudflare.com/'} if 'speed.cloudflare.com/' in url else {
               'Accept-Encoding': 'identity', 'Cache-Control': 'no-cache'}
    result = {'status': 'failed', 'url': url, 'requested_bytes': byte_count, 'budget_seconds': budget,
              'speed_mib_s': None, 'request_headers': headers, 'tls_verification_enabled': True,
              'deadline_mode': 'curl_total', 'received_bytes': 0}
    headers['User-Agent'] = WEB_USER_AGENT
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        args = ['curl', '--disable', '--silent', '--show-error', '--http1.1', '--proto', '=http,https',
                '--connect-timeout', '2', '--max-time', str(budget), '--max-filesize', str(byte_count),
                '--cacert', certifi.where(), '--noproxy', '', '--proxy', f'http://127.0.0.1:{port}',
                '--output', str(root / 'body'), '--dump-header', str(root / 'headers'), '--write-out', '%{json}']
        for key, value in headers.items():
            args += ['--header', f'{key}: {value}']
        try:
            process = subprocess.run(args + [url], capture_output=True, text=True, timeout=budget + 3)
            info = json.loads(process.stdout)
            raw = (root / 'headers').read_text(errors='replace') if (root / 'headers').exists() else ''
            block = raw.strip().replace('\r\n', '\n').split('\n\n')[-1]
            response_headers = {line.split(':', 1)[0].lower(): line.split(':', 1)[1].strip()
                                for line in block.splitlines() if ':' in line}
            elapsed = max(round(info['time_total'] * 1000, 1), .1)
            result.update(http_status=info['http_code'], elapsed_ms=elapsed,
                received_bytes=(root / 'body').stat().st_size if (root / 'body').exists() else 0,
                response_length=response_headers.get('content-length'), response_type=response_headers.get('content-type'),
                response_encoding=response_headers.get('content-encoding', 'identity'), curl_exit_code=process.returncode,
                ssl_verify_result=info['ssl_verify_result'], ttfb_ms=round(info['time_starttransfer'] * 1000, 1))
            valid = (process.returncode == 0 and info['url_effective'] == url and info['http_code'] == 200
                     and result['received_bytes'] == byte_count and result['response_length'] == str(byte_count)
                     and (result['response_type'] or '').split(';')[0] == 'application/octet-stream'
                     and result['response_encoding'] == 'identity' and elapsed <= budget * 1000
                     and info['ssl_verify_result'] == 0)
            if valid:
                result.update(status='passed', speed_mib_s=round(byte_count / (elapsed / 1000) / 1048576, 3))
            elif process.returncode:
                result['error_type'] = {28: 'timeout', 60: 'certificate_verification_failed', 35: 'tls_handshake_failed'}.get(
                    process.returncode, 'connection_or_protocol_failed')
            result['reason'] = '总时限内完整下载；含建连与首字节' if valid else '未完整下载、响应文件不符或超出总时限'
        except subprocess.TimeoutExpired:
            result.update(error_type='timeout', reason='下载进程超出总时限')
        except (OSError, KeyError, ValueError, TypeError):
            result.update(error_type='measurement_error', reason='下载测量工具或输出异常')
    return result
