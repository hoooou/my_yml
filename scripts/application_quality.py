"""Diagnostic application resources; failures are not new unvalidated hard gates."""
import html
import json
import re
import time
from urllib.parse import urljoin, urlsplit
import select_nodes as s
from mobile_pilot import WEB_USER_AGENT, tls_failure_kind

HOSTS = {'www.youtube.com', 'i.ytimg.com', 's.ytimg.com', 'yt3.ggpht.com'}
MAX_BYTES = 262144


def resources(body):
    found = []
    for value in re.findall(r'(?:src|href)=["\']([^"\']+)', body):
        try:
            url = urljoin('https://www.youtube.com/', html.unescape(value))
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            continue
        if (parts.scheme == 'https' and parts.hostname in HOSTS and port in (None, 443)
                and not parts.username and not parts.password
                and (parts.path.endswith(('.js', '.css', '.jpg', '.png', '.webp')))
                and url not in found):
            found.append(url)
    return found[:2]


def fetch(port, url, page=False, api=False):
    started = time.monotonic()
    result = {'status': 'failed', 'hostname': urlsplit(url).hostname, 'tls_verification_enabled': True,
              'sample_limit_bytes': MAX_BYTES if page else 65536}
    with s.session() as client:
        client.proxies = {'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'}
        try:
            with client.get(url, stream=True, verify=True, allow_redirects=False, timeout=(2, 3),
                    headers={'User-Agent': WEB_USER_AGENT, 'Accept-Encoding': 'identity'}) as response:
                result.update(http_status=response.status_code, ttfb_ms=round((time.monotonic()-started)*1000, 1))
                body = bytearray()
                complete = True
                for chunk in response.iter_content(4096):
                    body.extend(chunk[:result['sample_limit_bytes'] - len(body)])
                    if len(body) >= result['sample_limit_bytes'] or time.monotonic()-started >= 5:
                        complete = False
                        break
                result.update(sample_bytes=len(body), elapsed_ms=round((time.monotonic()-started)*1000, 1),
                              content_type=response.headers.get('Content-Type', ''), response_complete=complete)
                content_type = result['content_type'].split(';')[0].lower()
                expected_type = ('text/html' in content_type if page else 'json' in content_type if api else
                                 content_type in ('application/javascript', 'text/javascript', 'text/css') or content_type.startswith('image/'))
                if response.status_code == 200 and body and result['elapsed_ms'] <= 5000 and expected_type:
                    result['status'] = 'passed'
                return result, bytes(body)
        except s.requests.RequestException as error:
            result.update(error_type=type(error).__name__, elapsed_ms=round((time.monotonic()-started)*1000, 1))
            kind = tls_failure_kind(error)
            if kind:
                result['tls_error_kind'] = kind
    return result, b''


def check(port):
    page, body = fetch(port, 'https://www.youtube.com/', page=True)
    urls = resources(body.decode('utf-8', errors='replace')) if page['status'] == 'passed' and 'text/html' in page.get('content_type', '') else []
    probes = [fetch(port, url)[0] for url in urls]
    api, payload = fetch(port, 'https://api.openai.com/compliance/cookie_requirements', api=True)
    try:
        data = json.loads(payload)
        api['expected_json'] = (isinstance(data, dict) and isinstance(data.get('cookie_consent_required'), bool))
    except (ValueError, TypeError):
        api['expected_json'] = False
    if not api.get('response_complete') or not api['expected_json']:
        api['status'] = 'failed'
    return {'version': 1, 'status': 'diagnostic_only', 'youtube_page': page,
            'chatgpt_response_integrity': api,
            'youtube_resources': probes, 'resource_count': len(probes),
            'resource_passed_count': sum(x['status'] == 'passed' for x in probes),
            'authenticated_chat_tested': False, 'video_playback_tested': False,
            'new_resource_failure_is_hard_gate': False}
