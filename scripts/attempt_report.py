"""Archive each completed full measurement, including zero-qualified runs."""
from collections import Counter
import json
import app_tls
import high_speed
import medium_speed
import stability
import upload_speed


def write_attempt(root, records, config, required_sites, sources, input_count, now, required_traces=()):
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
        'confirmed_cloudflare_challenge': 'accepted_access_verification_required',
        'challenge_in_page_speed_ranking': False,
        'required_traces': list(required_traces), 'required_trace_rounds': 1,
        'app_tls_policy': {'version': app_tls.VERSION, 'targets': list(app_tls.TARGETS),
            'rounds_per_target': app_tls.ROUNDS, 'budget_seconds_per_handshake': app_tls.BUDGET_SECONDS,
            'android_certificate_pinning_emulated': False},
        'app_tls_counts': dict(Counter((r.get('app_tls') or {}).get('status', 'missing') for r in records)),
        'stability_policy': stability.settings(),
        'upload_policy': upload_speed.settings(),
        'upload_counts': dict(Counter((r.get('upload') or {}).get('status', 'not_candidate') for r in records)),
        'post_upload_tls_counts': dict(Counter((r.get('post_upload_tls') or {}).get('status', 'not_candidate') for r in records)),
        'stability_counts': dict(Counter((r.get('stability') or {}).get('status', 'not_candidate') for r in records)),
        'stability_failure_targets': dict(Counter(f['target'] for r in records
            for f in (r.get('stability') or {}).get('failures', []))),
        'precheck_counts': dict(Counter((r.get('precheck') or {}).get('status', 'missing') for r in records)),
        'entry_counts': dict(Counter(r['entry']['status'] for r in records)),
        'download_counts': dict(Counter((r.get('download') or {}).get('status', 'missing') for r in records)),
        'medium_speed_download_counts': medium_speed.counts(records),
        'medium_speed_download_settings': medium_speed.settings(),
        'high_speed_download_counts': high_speed.result_counts(records),
        'high_speed_download_settings': high_speed.settings(),
        'high_speed_target_counts': {url: high_speed.status_counts(records, i) for i, url in enumerate(high_speed.URLS)},
        'website_counts': coverage, 'sources': sources, 'nodes': records}
    rows = ['# 本次全量检测结果', '', f'检测结束：{now}；全部来源去重 {input_count}，可解析 {len(records)}，候选入选 {selected}。', '',
        '必过网站（三轮正常页面或明确CF验证）：' + '、'.join(required_sites) + '。', '',
        '必过连通检测（单轮）：' + ('、'.join(required_traces) if required_traces else '无') + '。', '',
        'CF需验证仅适用于预期HTTPS网站明确的cf-mitigated: challenge，不算访问失败；真实页面速度、204、trace及TLS仍独立判断。', '',
        'Claude首页不检测，仅检查Claude trace；trace不证明登录或对话可用。', '',
        '必过应用TLS：' + '、'.join(app_tls.TARGETS) + '；每个域名两次独立握手，校验可信证书链、域名和有效期。', '',
        '应用TLS结果：' + str(report['app_tls_counts']) + '。云端标准TLS检查不模拟Android证书固定，也不证明手机Wi-Fi路径正常。', '',
        '中速下载：1 MB通过后进行Cloudflare完整5 MB快测，预算10秒，仅真实通过进入中速组。', '',
        '高速下载：Cloudflare和DataPacket各完整100 MB，每轮20秒；两轮都通过才进入高速组，按两轮中较慢的速度排序。', '',
        '两轮均通过：' + str(report['high_speed_download_counts']) + '；逐目标结果：' + str(report['high_speed_target_counts']) + '。', '',
        '最终间隔稳定性：' + str(report['stability_counts']) + '；失败目标请求数：' + str(report['stability_failure_targets']) + '。', '',
        '上行：1MB预检后5MB两轮，每轮10秒、轮间20秒，取较低Mbps；上传后4个应用域名两次严格证书握手。上传结果：' + str(report['upload_counts']) + '；负载后证书：' + str(report['post_upload_tls_counts']) + '。云端请求完成不等于服务端逐字节接收回执，也不代表中国移动上行。', '',
        '下载后合格候选低并发复测5轮，轮间至少空闲30秒；204、Google、YouTube、ChatGPT trace及Android证书握手每轮均须通过，核心响应耗时仍须满足所在分组门槛。未进入该阶段的节点记为not_candidate，不冒充稳定性失败。IP变化不淘汰，所有分组保持手动选择；数分钟云端观察不证明长期稳定或手机ChatGPT持续对话正常。', '',
        '国内网页不逐节点检测；国内入口TCP及国内直连/DNS规则保留。', '',
        '有合格候选，继续校验并发布；最终发布状态以 Actions 为准。' if selected else
        '**本次无合格节点，未覆盖原订阅。原订阅仍是上次结果，不代表通过这次页面与trace必过门槛。**', '',
        '| 网站 | 通过 | 失败 | CF需验证 | 需复核 | 响应慢 | 波动 | 未测 |', '|---|---:|---:|---:|---:|---:|---:|---:|']
    for label, item in coverage.items():
        counts = item['node_status_counts']
        rows.append('| ' + label + ' | ' + ' | '.join(str(counts.get(s, 0))
            for s in ('passed', 'failed', 'verification_required', 'needs_review', 'slow', 'unstable')) + f' | {item["unmeasured_nodes"]} |')
    (root / 'full-test-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    (root / 'full-test-report.md').write_text('\n'.join(rows) + '\n')
    print(f'本次全量检测记录已保存：可解析 {len(records)}；候选入选 {selected}', flush=True)
