"""Bounded cloud-only inspection of website denials and redirects; no selection changes."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
import shutil
import time
from urllib.parse import urljoin, urlparse

import claude_diagnostics as c
import mobile_pilot as p
import select_nodes as s

LABELS = ('TikTok', 'Reddit', 'Gemini')
DENIAL_PHRASES = ('blocked by network security', 'request has been blocked', 'access denied',
    'unsupported country', 'not available in your country', 'not available in your region',
    'unusual traffic', 'sign in', 'log in', 'verify you are human', 'just a moment')


def evidence(label, status, url, headers, body):
    item = c.evidence(status, url, headers, body, label)
    lower = body.decode('utf-8', errors='replace').lower()
    item['denial_signals'] = {phrase: phrase in lower for phrase in DENIAL_PHRASES}
    item['body_sha256'] = __import__('hashlib').sha256(body).hexdigest()
    return item


def choose_samples(bundle, report, limit=4):
    available = {n['name'] for n in bundle['nodes']}
    tasks = []
    for label in LABELS:
        groups = {}
        for row in report['nodes']:
            page = (row.get('websites') or {}).get(label) or {}
            if row['id'] not in available or not page.get('attempts'):
                continue
            attempts = page['attempts']
            restricted = [a for a in attempts if a.get('status') == 'needs_review']
            group = ('redirect' if any(300 <= a.get('http_status', 0) < 400 for a in restricted)
                     else 'denied' if restricted else 'passed' if page.get('status') == 'passed' else None)
            if group:
                groups.setdefault(group, []).append(row)
        for group, rows in sorted(groups.items()):
            selected, exits = [], set()
            rows.sort(key=lambda row: row['id'])
            for row in rows:
                ip = (row.get('exit') or {}).get('exit_ip')
                if ip and ip in exits:
                    continue
                selected.append(row); exits.add(ip)
                if len(selected) == limit:
                    break
            for index, row in enumerate(selected):
                tasks.append({'row': row, 'label': label, 'group': group, 'browser': index < 2})
    return tasks


def requests_probe(port, label, ua, alternate_url=None):
    started = time.monotonic(); chain = []
    try:
        with s.session() as client:
            if port:
                client.proxies = {k: f'http://127.0.0.1:{port}' for k in ('http', 'https')}
            current = alternate_url or p.SITES[label]
            for hop in range(4):
                with client.get(current, headers={'User-Agent': ua}, allow_redirects=False,
                                stream=True, verify=True, timeout=(3, 2)) as response:
                    location = response.headers.get('Location')
                    target = urljoin(current, location) if location else None
                    chain.append({'http_status': response.status_code, 'url': c.safe_url(current),
                                  'location': c.safe_url(target) if target else None})
                    allowed = p.PAGE_HOSTS[label] | ({'accounts.google.com'} if label == 'Gemini' else set())
                    if (300 <= response.status_code < 400 and target and hop < 3
                            and urlparse(target).scheme == 'https' and urlparse(target).hostname in allowed):
                        current = target; continue
                    body = bytearray()
                    for chunk in response.iter_content(2048):
                        body.extend(chunk[:c.BODY_LIMIT - len(body)])
                        if len(body) >= c.BODY_LIMIT or time.monotonic() - started > 6:
                            break
                    return {**evidence(label, response.status_code, response.url, response.headers, bytes(body)),
                            'redirect_chain': chain, 'elapsed_ms': round((time.monotonic() - started) * 1000, 1)}
    except s.requests.RequestException as error:
        return {'error_type': type(error).__name__, 'redirect_chain': chain,
                **({'tls_error_kind': 'certificate_verification_failed'} if p.certificate_failure(error) else {}),
                'elapsed_ms': round((time.monotonic() - started) * 1000, 1)}


def browser_probe(port, label):
    from playwright.sync_api import sync_playwright, Error
    chain = []; started = time.monotonic()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, executable_path=shutil.which('google-chrome'))
            try:
                context = browser.new_context(proxy={'server': f'http://127.0.0.1:{port}'} if port else None,
                                              ignore_https_errors=False)
                page = context.new_page()
                def navigation(response):
                    if response.request.is_navigation_request() and response.frame == page.main_frame:
                        chain.append({'http_status': response.status, 'url': c.safe_url(response.url),
                            'headers': {k: v[:200] for k, v in response.headers.items()
                                if k in ('cf-mitigated', 'server', 'content-type')}})
                page.on('response', navigation)
                response = page.goto(p.SITES[label], wait_until='domcontentloaded', timeout=12000)
                page.wait_for_timeout(1500)
                headers = chain[-1]['headers'] if chain else (response.headers if response else {})
                status = chain[-1]['http_status'] if chain else (response.status if response else 0)
                visible = page.locator('body').inner_text(timeout=2000).encode()[:16384]
                result = evidence(label, status, page.url, headers, page.content().encode()[:c.BODY_LIMIT])
                result['visible_text_signals'] = {phrase: phrase in visible.decode('utf-8', errors='replace').lower()
                    for phrase in DENIAL_PHRASES}
                result['rendered_title'] = page.title()[:160]
                return {**result,
                    'redirect_chain': chain, 'elapsed_ms': round((time.monotonic() - started) * 1000, 1)}
            finally:
                browser.close()
    except Error as error:
        return {'error_type': type(error).__name__, 'redirect_chain': chain,
                'elapsed_ms': round((time.monotonic() - started) * 1000, 1)}


def inspect(port, task):
    label = task['label']; row = task['row']
    item = {'node_id': row['id'], 'label': label, 'original_group': task['group'],
            'country': (row.get('exit') or {}).get('country_code'),
            'original_attempts': [{k: a[k] for k in ('status', 'http_status', 'restriction') if k in a}
                for a in ((row.get('websites') or {}).get(label) or {}).get('attempts', [])],
            'bot': requests_probe(port, label, p.LEGACY_WEB_USER_AGENT),
            'browser_ua': requests_probe(port, label, c.BROWSER_UA)}
    item['production_rounds'] = [p.check_site(port, label, p.SITES[label]) for _ in range(3)]
    if label == 'Reddit':
        item['old_reddit'] = requests_probe(port, label, c.BROWSER_UA, 'https://old.reddit.com/')
    if task['browser']:
        item['browser'] = browser_probe(port, label)
    return item


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True); parser.add_argument('--bundle', required=True)
    parser.add_argument('--report', required=True)
    parser.add_argument('--work-dir', default='.node-work/website-diagnostics')
    args = parser.parse_args()
    root = Path(args.work_dir).resolve(); root.mkdir(parents=True, exist_ok=True)
    bundle = json.loads(Path(args.bundle).read_text()); report = json.loads(Path(args.report).read_text())
    tasks = choose_samples(bundle, report)
    if not tasks:
        raise RuntimeError('No mapped website samples')
    rows = {task['row']['id']: task['row'] for task in tasks}
    mapping = {node['name']: node for node in bundle['nodes']}
    listeners, ports = s.make_listeners(rows.values())
    with s.Core(str(Path(args.mihomo).resolve()), root, [mapping[key] for key in rows], listeners):
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda task: inspect(ports[task['row']['id']], task), tasks))
    results += [inspect(None, {'row': {'id': 'github-direct'}, 'label': label,
                             'group': 'direct_control', 'browser': True}) for label in LABELS]
    output = {'scope': 'diagnostic_only', 'source_report_updated_at': report['updated_at'], 'results': results}
    (root / 'summary.json').write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n')
    for item in results:
        print(item['label'], item['original_group'], item['node_id'],
              {k: item[k].get('http_status', item[k].get('error_type')) for k in
               ('bot', 'browser_ua', 'browser', 'old_reddit') if k in item}, flush=True)


if __name__ == '__main__':
    main()
