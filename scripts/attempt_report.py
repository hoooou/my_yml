"""Archive each completed full measurement, including zero-qualified runs."""
from collections import Counter
import json


def write_attempt(root, records, config, required_sites, sources, input_count, now):
    coverage = {}
    labels = {label for record in records for label in (record.get('websites') or {})}
    for label in sorted(labels):
        items = [(r.get('websites') or {}).get(label) for r in records]
        measured = [item for item in items if item]
        attempts = [attempt for item in measured for attempt in item.get('attempts', [])]
        coverage[label] = {'node_status_counts': dict(Counter(item['status'] for item in measured)),
            'unmeasured_nodes': len(items) - len(measured),
            'attempt_http_status_counts': dict(Counter(str(a.get('http_status', 'no_response')) for a in attempts)),
            'attempt_reason_counts': dict(Counter(a.get('reason', 'unknown') for a in attempts))}
    selected = len(config['proxies'])
    report = {'updated_at': now, 'scope': 'all_subscriptions', 'input_unique_count': input_count,
        'parseable_count': len(records), 'selected_node_count': selected,
        'selection_outcome': 'candidate_ready' if selected else 'no_eligible_nodes_previous_subscription_retained',
        'required_websites': list(required_sites), 'required_rounds': 3,
        'precheck_counts': dict(Counter((r.get('precheck') or {}).get('status', 'missing') for r in records)),
        'entry_counts': dict(Counter(r['entry']['status'] for r in records)),
        'download_counts': dict(Counter((r.get('download') or {}).get('status', 'missing') for r in records)),
        'high_speed_download_counts': dict(Counter((r.get('high_speed_download') or {}).get('status', 'missing') for r in records)),
        'website_counts': coverage, 'sources': sources, 'nodes': records}
    rows = ['# 本次全量检测结果', '', f'检测结束：{now}；全部来源去重 {input_count}，可解析 {len(records)}，候选入选 {selected}。', '',
        '必过网站（三轮均通过）：' + '、'.join(required_sites) + '。', '',
        '抖音不检测；其国内直连规则保留。', '',
        '有合格候选，继续校验并发布；最终发布状态以 Actions 为准。' if selected else
        '**本次无合格节点，未覆盖原订阅。原订阅仍是上次结果，不代表通过这次13站必过门槛。**', '',
        '| 网站 | 通过 | 失败 | 需复核 | 响应慢 | 波动 | 未测 |', '|---|---:|---:|---:|---:|---:|---:|']
    for label, item in coverage.items():
        counts = item['node_status_counts']
        rows.append('| ' + label + ' | ' + ' | '.join(str(counts.get(s, 0))
            for s in ('passed', 'failed', 'needs_review', 'slow', 'unstable')) + f' | {item["unmeasured_nodes"]} |')
    (root / 'full-test-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    (root / 'full-test-report.md').write_text('\n'.join(rows) + '\n')
    print(f'本次全量检测记录已保存：可解析 {len(records)}；候选入选 {selected}', flush=True)
