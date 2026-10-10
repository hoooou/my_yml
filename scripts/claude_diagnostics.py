#!/usr/bin/env python3
"""Bounded, diagnostic-only Claude comparisons; never publish or relax criteria."""
import argparse
import concurrent.futures as futures
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from urllib.parse import urljoin, urlparse, urlunparse

import mobile_pilot as p
import select_nodes as s

BODY_LIMIT = 131072
BROWSER_UA = ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36')


def safe_url(url):
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.hostname or '', parsed.path[:240], '', '', ''))


def choose_samples(nodes, rows, limit):
    available = {n['name'] for n in nodes}
    candidates = [r for r in rows if r['id'] in available and all(
        (r.get('websites') or {}).get(k, {}).get('status') == 'passed'
        for k in ('Google', 'YouTube', 'ClaudeTrace'))]
    # First cover distinct measured countries; never infer country from node names.
    preferred = ['US', 'FR', 'DE', 'NL', 'GB', 'SG', 'TW', 'JP', 'HK']
    order = {country: i for i, country in enumerate(preferred)}
    candidates.sort(key=lambda r: (order.get((r.get('exit') or {}).get('country_code'), 99), r['id']))
    selected, countries, exits = [], set(), set()
    for row in candidates:
        country = (row.get('exit') or {}).get('country_code')
        ip = (row.get('exit') or {}).get('exit_ip')
        if not country or not ip or country in countries or ip in exits:
            continue
        selected.append(row); countries.add(country); exits.add(ip)
        if len(selected) == limit:
            break
    return selected


def evidence(status, url, headers, body):
    headers = {k.lower(): v for k, v in headers.items()}
    text = body.decode('utf-8', errors='replace')
    lower = text.lower()
    title = re.search(r'<title\b[^>]*>(.*?)</title>', text, re.I | re.S)
    selected_headers = {k: headers[k][:200] for k in
        ('content-type', 'server', 'cf-mitigated', 'cf-ray', 'retry-after') if k in headers}
    if headers.get('location'):
        selected_headers['location'] = safe_url(urljoin(url, headers['location']))
    url = safe_url(url)
    return {'http_status': status, 'url': url, 'headers': selected_headers,
        'sample_bytes': len(body), 'title': re.sub(r'\s+', ' ', title[1])[:160] if title else None,
        'challenge_signals': {'cf_mitigated': headers.get('cf-mitigated') == 'challenge',
            'cf_chl': 'cf-chl-' in lower, 'just_a_moment': 'just a moment' in lower,
            'verify_human': 'verify you are human' in lower,
            'unsupported_country': ('unsupported_country' in lower or 'unsupported country' in lower
                or 'app unavailable in region' in lower
                or '/app-unavailable-in-region' in selected_headers.get('location', '')
                or urlparse(url).path.rstrip('/') == '/app-unavailable-in-region')},
        'classification': p.classify_response('Claude', status, url, headers, body[:p.PAGE_SAMPLE_BYTES]),
        'larger_sample_classification': p.classify_response('Claude', status, url, headers, body)}


def requests_probe(port, ua):
    started = time.monotonic()
    chain = []
    try:
        with s.session() as client:
            if port:
                client.proxies = {k: f'http://127.0.0.1:{port}' for k in ('http', 'https')}
            current = p.SITES['Claude']
            for hop in range(3):
                with client.get(current, headers={'User-Agent': ua}, allow_redirects=False,
                                stream=True, timeout=(3, 2)) as response:
                    headers_ms = round((time.monotonic() - started) * 1000, 1)
                    location = response.headers.get('Location')
                    chain.append({'http_status': response.status_code, 'url': safe_url(current),
                                  'location': safe_url(urljoin(current, location)) if location else None})
                    if 300 <= response.status_code < 400 and location and hop < 2:
                        target = urljoin(current, location)
                        if urlparse(target).scheme == 'https' and urlparse(target).hostname in p.PAGE_HOSTS['Claude']:
                            current = target
                            continue
                    body = bytearray()
                    for chunk in response.iter_content(1024):
                        body.extend(chunk[:BODY_LIMIT - len(body)])
                        if len(body) >= BODY_LIMIT or time.monotonic() - started > 5:
                            break
                    return {**evidence(response.status_code, response.url, response.headers, bytes(body)),
                        'ttfb_ms': headers_ms, 'elapsed_ms': round((time.monotonic() - started) * 1000, 1),
                        'redirect_chain': chain}
    except s.requests.RequestException as error:
        return {'error_type': type(error).__name__, 'redirect_chain': chain,
                'elapsed_ms': round((time.monotonic() - started) * 1000, 1)}


def curl_probe(port, version):
    with tempfile.TemporaryDirectory(prefix='claude-curl-') as directory:
        root = Path(directory)
        command = ['curl', '--silent', '--show-error', '--compressed', '--' + version,
            '--connect-timeout', '3', '--max-time', '8', '--max-filesize', str(BODY_LIMIT),
            '--user-agent', BROWSER_UA, '--dump-header', str(root / 'headers'),
            '--output', str(root / 'body'), '--write-out', '%{json}', p.SITES['Claude']]
        if port:
            command[1:1] = ['--proxy', f'http://127.0.0.1:{port}']
        else:
            command[1:1] = ['--noproxy', '*']
        result = subprocess.run(command, capture_output=True, text=True, timeout=12)
        try:
            stats = json.loads(result.stdout)
        except ValueError:
            return {'curl_exit_code': result.returncode, 'error_type': 'no_curl_response'}
        raw_headers = (root / 'headers').read_text(errors='replace') if (root / 'headers').exists() else ''
        header_block = raw_headers.strip().split('\n\n')[-1]
        headers = dict(line.split(':', 1) for line in header_block.splitlines() if ':' in line)
        headers = {k.strip(): v.strip() for k, v in headers.items()}
        body = (root / 'body').read_bytes()[:BODY_LIMIT] if (root / 'body').exists() else b''
        return {**evidence(stats.get('http_code', 0), stats.get('url_effective', p.SITES['Claude']), headers, body),
            'curl_exit_code': result.returncode, 'http_version': stats.get('http_version'),
            'ttfb_ms': round(stats.get('time_starttransfer', 0) * 1000, 1),
            'elapsed_ms': round(stats.get('time_total', 0) * 1000, 1)}


def browser_probe(port):
    from playwright.sync_api import sync_playwright, Error
    started = time.monotonic()
    chain = []
    try:
        with sync_playwright() as playwright:
            # Ordinary headless Chrome; no stealth, captcha solving or shared clearance cookies.
            executable = shutil.which('google-chrome') or shutil.which('chromium')
            browser = playwright.chromium.launch(headless=True, executable_path=executable)
            try:
                context = browser.new_context(proxy={'server': f'http://127.0.0.1:{port}'} if port else None)
                page = context.new_page()
                page.on('response', lambda response: chain.append({
                    'http_status': response.status, 'url': safe_url(response.url),
                    'headers': {k: v[:200] for k, v in response.headers.items()
                                if k in ('cf-mitigated', 'server', 'content-type')}})
                    if response.request.is_navigation_request() and response.frame == page.main_frame else None)
                response = page.goto(p.SITES['Claude'], wait_until='domcontentloaded', timeout=15000)
                page.wait_for_timeout(2000)
                body = page.content().encode()[:BODY_LIMIT]
                status = chain[-1]['http_status'] if chain else (response.status if response else 0)
                headers = chain[-1]['headers'] if chain else (response.headers if response else {})
                return {**evidence(status, page.url, headers, body), 'redirect_chain': chain,
                    'browser_version': browser.version, 'user_agent': page.evaluate('navigator.userAgent'),
                    'elapsed_ms': round((time.monotonic() - started) * 1000, 1)}
            finally:
                browser.close()
    except Error as error:
        return {'error_type': type(error).__name__, 'redirect_chain': chain,
                'elapsed_ms': round((time.monotonic() - started) * 1000, 1)}


def control_probe(port, label):
    if port:
        return p.check_site(port, label, p.SITES[label])
    if label == 'Claude':
        result = requests_probe(None, p.WEB_USER_AGENT)
        return {**result.get('classification', {'status': 'failed'}),
                'elapsed_ms': result.get('elapsed_ms'), 'redirect_hops': len(result.get('redirect_chain', [])) - 1}
    started = time.monotonic()
    try:
        with s.session() as client:
            with client.get(p.SITES[label], headers={'User-Agent': p.WEB_USER_AGENT},
                            allow_redirects=False, stream=True, timeout=(3, 2)) as response:
                body = bytearray()
                for chunk in response.iter_content(1024):
                    body.extend(chunk[:p.PAGE_SAMPLE_BYTES - len(body)])
                    if len(body) >= p.PAGE_SAMPLE_BYTES or time.monotonic() - started > 5:
                        break
                return {**p.classify_response(label, response.status_code, response.url,
                        response.headers, bytes(body)),
                        'elapsed_ms': round((time.monotonic() - started) * 1000, 1)}
    except s.requests.RequestException as error:
        return {'status': 'failed', 'error_type': type(error).__name__}


def inspect(port, row):
    def controls():
        return {label: control_probe(port, label)
                for label in ('Google204', 'ClaudeTrace')}
    result = {'id': row['id'], 'previous_exit': row.get('exit'),
              'previous_claude': (row.get('websites') or {}).get('Claude'), 'before': controls()}
    result['production_probe'] = control_probe(port, 'Claude')
    # The two Requests comparisons differ only by User-Agent.
    result['requests_bot'] = [requests_probe(port, p.WEB_USER_AGENT) for _ in range(2)]
    result['requests_browser_ua'] = [requests_probe(port, BROWSER_UA) for _ in range(2)]
    # The two curl comparisons differ only by HTTP-version preference.
    result['curl_http1'] = curl_probe(port, 'http1.1')
    result['curl_http2'] = curl_probe(port, 'http2')
    result['browser'] = browser_probe(port)
    result['after'] = controls()
    print('Claude diagnostic completed: ' + row['id'], flush=True)
    return result


def markdown(results):
    lines = ['# Claude 首页诊断', '', '仅用于对照诊断，不修改订阅或13站必过规则；403和验证页不计通过。', '',
        '|样本|上轮→本次出口|204/trace控制前→后|现有检测|Requests原UA|Requests浏览器UA|curl H1/H2|普通Chrome|',
        '|---|---|---|---|---|---|---|---|']
    def label(item):
        signals = item.get('challenge_signals', {})
        extra = ' 验证页' if (item.get('restriction') == 'cloudflare_challenge' or any(
            signals.get(k) for k in ('cf_mitigated', 'cf_chl', 'just_a_moment', 'verify_human'))) else ''
        if signals.get('unsupported_country') or item.get('restriction') == 'region_unavailable':
            extra += ' 地区限制'
        return str(item.get('http_status', item.get('error_type', item.get('status', '?')))) + extra
    for r in results:
        controls = '/'.join(r['before'][k]['status'] for k in ('Google204', 'ClaudeTrace')) + ' → ' + '/'.join(r['after'][k]['status'] for k in ('Google204', 'ClaudeTrace'))
        previous = (r.get('previous_exit') or {}).get('country_code', '云端直连')
        current = r['before']['ClaudeTrace'].get('country_code', '未知')
        country = previous + ' → ' + current if previous != current else current
        cells = [r['id'], country, controls,
            label(r['production_probe']), ', '.join(map(label, r['requests_bot'])),
            ', '.join(map(label, r['requests_browser_ua'])), label(r['curl_http1']) + '/' + label(r['curl_http2']), label(r['browser'])]
        lines.append('|' + '|'.join(cells) + '|')
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--report', required=True)
    parser.add_argument('--work-dir', default='.node-work/claude-diagnostics')
    parser.add_argument('--samples', type=int, default=8)
    args = parser.parse_args()
    root = Path(args.work_dir).resolve(); root.mkdir(parents=True, exist_ok=True)
    bundle = json.loads(Path(args.bundle).read_text())
    report = json.loads(Path(args.report).read_text())
    rows = choose_samples(bundle['nodes'], report['nodes'], args.samples)
    if not rows:
        raise RuntimeError('没有可映射到本轮输入的健康对照样本')
    mapping = {n['name']: n for n in bundle['nodes']}
    listeners, ports = s.make_listeners(rows)
    with s.Core(str(Path(args.mihomo).resolve()), root, [mapping[r['id']] for r in rows], listeners):
        with futures.ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda r: inspect(ports[r['id']], r), rows))
    # Same runner, no proxy: separate cloud-runner access policy from exit-node effects.
    results.append(inspect(None, {'id': 'github-direct', 'exit': None}))
    (root / 'summary.json').write_text(json.dumps({'scope': 'diagnostic_only',
        'source_report_updated_at': report['updated_at'], 'results': results}, ensure_ascii=False, indent=2) + '\n')
    (root / 'summary.md').write_text(markdown(results))
    print(markdown(results), flush=True)


if __name__ == '__main__':
    main()
