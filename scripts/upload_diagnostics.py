"""Read-only pilot against the currently published pool, entirely in Actions."""
import argparse
import json
from pathlib import Path
import yaml

import app_tls
import select_nodes as s
import stability
import upload_speed as up


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True)
    args = parser.parse_args()
    binary = str(Path(args.mihomo).resolve())
    root = Path('.node-work/upload-diagnostics').resolve(); root.mkdir(parents=True, exist_ok=True)
    report = json.loads(Path('连通性报告.json').read_text())
    config = yaml.safe_load(Path('优选配置.yaml').read_text())
    by_name = {n['name']: n for n in config['proxies']}
    records = [dict(r) for r in report['nodes'] if r['id'] in report['published_node_ids']]
    mapping = {r['id']: {**by_name[r['name']], 'name': r['id']} for r in records}
    diagnostic = up.recheck(records, mapping, binary, root)
    listeners, ports = s.make_listeners(records)
    with s.Core(binary, root, list(mapping.values()), listeners):
        for row in records:
            row['post_upload_tls'] = app_tls.check(ports[row['id']])
    diagnostic['post_upload_tls'] = [{'id': r['id'], 'tls': r['post_upload_tls']} for r in records]
    (root / 'upload-results.json').write_text(json.dumps(diagnostic, ensure_ascii=False, indent=2) + '\n')
    stable = stability.recheck(records, mapping, binary, root)
    print('上传后五轮全通过：' + str(sum(stability.passed(r['stability']) for r in records)), flush=True)
    print('只读小样本完成；未更新订阅', flush=True)


if __name__ == '__main__':
    main()
