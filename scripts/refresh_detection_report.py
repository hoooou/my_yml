"""Refresh presentation from existing evidence; never probe or change selection."""
import json
from pathlib import Path
import yaml

import availability as a
from detection_report import latest_cohort, website_access_summary
from latest_report import write_latest


def refresh(root):
    root = Path(root)
    path = root / '连通性报告.json'
    report = json.loads(path.read_text())
    # A newer zero-candidate attempt must never be replaced by the old subscription.
    if (root / '最新检测.json').exists():
        print('最新检测摘要已生成；保留本轮记录，不用旧订阅测量覆盖', flush=True)
        return
    config = yaml.safe_load((root / '优选配置.yaml').read_text())
    names = {node['name'] for node in config['proxies']}
    published = {row['id'] for row in report['nodes'] if row.get('name') in names}
    if published != set(report['published_node_ids']) or len(names) != len(published):
        raise ValueError('已发布配置与报告节点不一致，拒绝刷新')
    report['website_access_summary'] = website_access_summary(latest_cohort(report))
    write_latest(report, config, root, website_gate=a.required_websites_passed, validation='historical_verified')
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print('已按原测量刷新逐网站统计；未重新测速或改变节点', flush=True)


if __name__ == '__main__':
    refresh(Path('.'))
