"""Refresh presentation from existing evidence; never probe or change selection."""
import json
from pathlib import Path
import yaml

import availability as a
from detection_report import latest_cohort, website_access_summary, write_report


def refresh(root):
    root = Path(root)
    path = root / '连通性报告.json'
    report = json.loads(path.read_text())
    config = yaml.safe_load((root / '优选配置.yaml').read_text())
    names = {node['name'] for node in config['proxies']}
    published = {row['id'] for row in report['nodes'] if row.get('name') in names}
    if published != set(report['published_node_ids']) or len(names) != len(published):
        raise ValueError('已发布配置与报告节点不一致，拒绝刷新')
    report['website_access_summary'] = website_access_summary(latest_cohort(report))
    write_report(report, config, root / '连通性报告.md', website_gate=a.required_websites_passed)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print('已按原测量刷新逐网站统计；未重新测速或改变节点', flush=True)


if __name__ == '__main__':
    refresh(Path('.'))
