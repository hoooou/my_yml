#!/usr/bin/env python3
"""Inspect bounded Amazon samples; diagnostic results never change pass criteria."""
import argparse
import concurrent.futures as futures
import json
from pathlib import Path
import re
import time

import yaml
import select_nodes as s
import mobile_pilot as p


def inspect(port, node_id):
    started = time.monotonic()
    try:
        with s.session() as client:
            client.proxies = {k: f'http://127.0.0.1:{port}' for k in ('http', 'https')}
            with client.get(p.SITES['Amazon'], headers={'User-Agent': p.WEB_USER_AGENT},
                            stream=True, allow_redirects=False, timeout=(3, 2)) as response:
                body = bytearray()
                for chunk in response.iter_content(4096):
                    body.extend(chunk[:262144 - len(body)])
                    if len(body) >= 262144 or time.monotonic() - started >= 5:
                        break
                raw = bytes(body)
                title = re.search(br'<title[^>]*>(.*?)</title>', raw, re.S | re.I)
                return {'node_id': node_id, 'http_status': response.status_code,
                    'content_type': response.headers.get('Content-Type', ''), 'sample_bytes': len(raw),
                    'first_brand_byte': raw.lower().find(b'amazon'),
                    'title': title[1].decode('utf-8', errors='replace')[:150] if title else None,
                    'prefix_classification': {str(size): p.classify_page('Amazon', response.status_code,
                        response.url, response.headers.get('Content-Type', ''), raw[:size])
                        for size in (16384, 65536, 131072, 262144)}}
    except s.requests.RequestException:
        return {'node_id': node_id, 'status': 'connection_failed'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--work-dir', default='.node-work/page-diagnostics')
    args = parser.parse_args()
    root = Path(args.work_dir).resolve(); root.mkdir(parents=True, exist_ok=True)
    nodes = [{**n, 'name': f'sample-{i}'} for i, n in enumerate(
        yaml.safe_load(Path('优选配置.yaml').read_text()).get('proxies', [])[:3])]
    results = []
    if nodes:
        listeners, ports = s.make_listeners({'id': n['name']} for n in nodes)
        with s.Core(str(Path(args.mihomo).resolve()), root, nodes, listeners):
            with futures.ThreadPoolExecutor(max_workers=3) as pool:
                results = list(pool.map(lambda n: inspect(ports[n['name']], n['name']), nodes))
    (root / 'summary.json').write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(results, ensure_ascii=False, indent=2), flush=True)


if __name__ == '__main__':
    main()
