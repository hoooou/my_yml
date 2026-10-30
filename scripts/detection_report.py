"""One compact report for the current selection; raw evidence stays in JSON."""
from datetime import datetime
import math
from pathlib import Path

import app_tls
import high_speed
import medium_speed
from select_nodes import COUNTRIES
import stability
import continuous_stability as cs
import upload_speed
import service_probes
import quality_policy as qp
from mobile_pilot import confirmed_cloudflare_challenge, confirmed_reddit_login, confirmed_page_exception


def website_access_summary(nodes):
    """Count affected nodes, never confuse three attempts with three nodes."""
    labels = {label for row in nodes for label in (row.get('websites') or {}) if label != 'Google204'}
    result = {}
    modern = any(qp.modern(r) for r in nodes)
    for label in sorted(labels):
        stats = dict.fromkeys(('measured', 'accepted', 'cloudflare_challenge', 'login_required', 'restricted',
                              'transport_error', 'http_error', 'page_or_speed_error', 'unmeasured'), 0)
        if modern:
            stats.update(tls_error=0, recovered_transport=0, timeout_error=0)
        for row in nodes:
            item = (row.get('websites') or {}).get(label) or {}
            if item.get('status', 'missing') in ('missing', 'skipped', 'unknown', 'not_candidate'):
                stats['unmeasured'] += 1
                continue
            stats['measured'] += 1
            attempts = item.get('attempts') or [item]
            cf = [x.get('status') == 'verification_required' and confirmed_cloudflare_challenge(label, x)
                  for x in attempts]
            accepted = item.get('status') == 'passed' or (
                item.get('status') in ('verification_required', 'login_required')
                and all(x.get('status') == 'passed' or confirmed_page_exception(label, x) for x in attempts))
            if qp.modern(row):
                accepted = qp.accepted(label, item, confirmed_page_exception, trace=label.endswith('Trace'))
            stats['accepted'] += accepted
            if modern:
                stats['tls_error'] += any(qp.tls_errors(x) for x in attempts)
                stats['recovered_transport'] += accepted and any(qp.transient(x) for x in attempts)
                stats['timeout_error'] += any(x.get('error_type') in ('ReadTimeout', 'ConnectTimeout', 'Timeout', 'timeout') for x in attempts)
            stats['cloudflare_challenge'] += any(cf)
            stats['login_required'] += any(x.get('status') == 'login_required' and confirmed_reddit_login(label, x) for x in attempts)
            stats['restricted'] += any(x.get('status') in ('needs_review', 'verification_required', 'login_required')
                                      and not confirmed_page_exception(label, x) for x in attempts)
            stats['transport_error'] += any(x.get('error_type') or x.get('tls_error_kind') for x in attempts)
            stats['http_error'] += any(x.get('status') in ('failed', 'slow')
                and (x.get('http_status') or 0) >= 400 for x in attempts)
            stats['page_or_speed_error'] += any(x.get('status') in ('failed', 'slow')
                and not x.get('error_type') and not x.get('tls_error_kind')
                and (x.get('http_status') or 0) < 400 for x in attempts)
        result[label] = stats
    return result


def website_access_table(nodes, required=()):
    counts = website_access_summary(nodes)
    if not counts:
        return []
    rows = ['## 各网站拦截与异常数量', '',
            f'统计范围 **{len(nodes)}** 个节点；仅实测节点进入各站分母。带★为逐站必过目标，其余目标仍参与整体覆盖率和证书校验。', '',
            '| 网站 | 实测 | 通过 | CF人机验证 | 登录提示（通过） | 其他拦截／跳转 | 连接／TLS异常 | HTTP错误 | 慢／内容异常 |',
            '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for label, item in sorted(counts.items(), key=lambda kv: (-(kv[1]['measured'] - kv[1]['accepted']), kv[0])):
        rows.append('| ' + ('★ ' if label in required else '') + cell(label) + ' | ' +
                    ' | '.join(str(item[k]) for k in ('measured', 'accepted', 'cloudflare_challenge', 'login_required',
                        'restricted', 'transport_error', 'http_error', 'page_or_speed_error')) + ' |')
    rows += ['', '数量按涉及节点计算，同一节点三轮中重复失败只计一个。通过包含已确认的Cloudflare人机验证及Reddit明确登录提示；没有这两类证据的普通403、429或跳转列入其他拦截／跳转，不能当作线路断开。异常原因列可能重叠，不相加。未测节点不算失败；完整数量见JSON的website_access_summary。', '']
    if any(qp.modern(r) for r in nodes):
        rows += ['新版逐站通过允许一次普通连接失败且另外两次认可可达；已恢复的超时仍保留在异常计数。TLS、超时和恢复通过数量在JSON分别记录，任何TLS异常都不放行。', '']
    anomalies = [label for label, x in counts.items() if label in required and x['measured'] >= 10 and not x['accepted']]
    if anomalies:
        rows += ['**必过站全失败，需检查检测器和服务响应：' + '、'.join(sorted(anomalies)) + '。** 不据此断言所有节点线路失效；保留原始结果，未自动放宽筛选。', '']
    return rows


def cell(value):
    return str(value).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')


def service_checks_table(nodes):
    counts = service_probes.summary(nodes)
    if not any(x['measured'] for x in counts.values()):
        return []
    rows = ['## 补充服务检测', '',
        'FAST在1MB下载通过后检测；独立于网站覆盖率和下载分组，普通接口异常不淘汰节点，明确证书校验错误仍淘汰。', '',
        '| 检测 | 实测 | 通过 | 限制 | CF验证 | 接口不可用／未知 | 连接／下载失败 | 证书错误 |',
        '|---|---:|---:|---:|---:|---:|---:|---:|']
    for label, title in (('ChatGPTAPI', 'ChatGPT API'), ('FASTAPI', 'FAST测速API'),
                         ('FAST', 'Netflix CDN（按节点）')):
        x = counts[label]
        if label == 'ChatGPTAPI' and not x['measured']:
            continue
        rows.append(f'| {title} | {x["measured"]} | {x["passed"]} | {x["restricted"]} | '
            f'{x["verification_required"]} | {x["unavailable"] + x["unknown"]} | {x["failed"]} | {x["certificate_error"]} |')
    cdn = service_probes.cdn_summary(nodes)
    multi = any('downloads' in (r.get('service_checks') or {}).get('targets', {}).get('FAST', {}) for r in nodes)
    policy = '请求3个不同CDN主机，依次各下载1MB、各限6秒；3个都通过才记为FAST通过，不足3个记为未知' if multi else '取得可信目标并在6秒内完整下载1MB'
    rows += ['', f'CDN文件实测{cdn["measured"]}次：通过{cdn["passed"]}次，失败{cdn["failed"]}次（其中证书错误{cdn["certificate_error"]}次）。', '',
        f'API通过表示取得预期响应；FAST{policy}。均不代表登录、对话、视频播放或内容解锁成功。FAST API失败时CDN下载未测；JSON分别记录每个目标的状态、速度和成功样本速度范围／中位数。证书错误列可能与其他原因重叠。', '']
    return rows


def number(value, digits=0):
    return f'{value:.{digits}f}' if type(value) in (int, float) and math.isfinite(value) else '—'


def clock(value):
    if not value:
        return '未记录'
    try:
        from datetime import timezone, timedelta
        return datetime.fromisoformat(value).astimezone(timezone(timedelta(hours=8))).strftime('%m-%d %H:%M:%S')
    except (TypeError, ValueError):
        return '未记录'


def group_counts(config):
    names = {n['name'] for n in config.get('proxies', [])}
    return [(g['name'], len(set(g.get('proxies', [])) & names))
            for g in config.get('proxy-groups', []) if g['name'] != '🚀 全局选择']


def latest_cohort(report):
    if report.get('publication_mode', 'full') == 'full':
        return report.get('nodes', [])
    # Compare the timestamps of actual measurements, never the report rewrite.
    batches = [report.get(key) for key in ('upload_recheck', 'stability_recheck')
               if (report.get(key) or {}).get('node_ids')]
    if batches:
        latest = max(batches, key=lambda x: datetime.fromisoformat(x['updated_at']))
        ids = set(latest['node_ids'])
        return [r for r in report['nodes'] if r['id'] in ids]
    ids = set(report.get('published_node_ids', []))
    return [r for r in report['nodes'] if r['id'] in ids]


def download(row):
    for key, validator, label in (
            ('high_speed_download', high_speed.passed, '100MB'),
            ('medium_speed_download', medium_speed.passed, '5MB'),
            ('download', lambda x: x.get('status') == 'passed', '1MB')):
        item = row.get(key) or {}
        if validator(item):
            speed = item.get('speed_mib_s')
            return f'{number(speed * 8.388608, 1)} / {label}' if type(speed) in (int, float) else '—'
    return '—'


def ssl_passed(row):
    explicit_error = any(a.get('tls_error_kind') == 'certificate_verification_failed'
        for item in (row.get('websites') or {}).values() for a in item.get('attempts', [item]))
    return (not explicit_error and not service_probes.certificate_errors(row.get('service_checks')) and app_tls.passed(row.get('app_tls'))
            and app_tls.passed(row.get('post_upload_tls')))


def upload_failure(row):
    item = row.get('upload') or {}
    if not item:
        return '上行未测'
    if not upload_speed.sample_passed(item.get('precheck') or {}, upload_speed.PRECHECK_BYTES, upload_speed.PRECHECK_BUDGET):
        return '3MB上传预检未通过'
    attempts = item.get('attempts', [])
    if any(a.get('curl_exit_code') == 28 for a in attempts):
        return '5MB上传请求超时（10秒）'
    if any(p.get('status') != 'passed' or not stability.finite(p.get('elapsed_ms'))
           or not 0 <= p['elapsed_ms'] <= 5000
           for a in attempts for p in a.get('loaded_204', [])):
        return '上传期间204异常或超时'
    return '两轮上传或完整验证证据未通过'


def stability_details(nodes):
    """Explain the latest real rounds without trusting cached pass counts."""
    continuous = [r['stability'] for r in nodes if (r.get('stability') or {}).get('version') in cs.VERSIONS]
    if continuous:
        stats = [cs.metrics(x) for x in continuous]
        good = sum(stability.passed(x) for x in continuous)
        low_rate = sum(x['success_rate'] < .90 for x in stats)
        certs = sum(any(cs.certificate_error(a) for a in x['attempts']) for x in continuous)
        rounds = [x['round_count'] for x in stats]
        return [f'持续稳定性：**{len(continuous)}**个候选，每节点**{min(rounds)}～{max(rounds)}**轮；通过**{good}**个，成功率低于90% **{low_rate}**个，明确证书错误 **{certs}**个。原因可能重叠。']
    measured = [r['stability'] for r in nodes if len((r.get('stability') or {}).get('attempts', [])) == stability.ROUNDS]
    if not measured:
        return []
    distribution, targets = {}, {}
    for item in measured:
        good = sum(stability.round_passed(x) for x in item['attempts'])
        distribution[good] = distribution.get(good, 0) + 1
        failed_targets = set()
        for attempt in item['attempts']:
            for label in stability.TARGETS:
                sample = (attempt.get('sites') or {}).get(label) or {}
                if sample.get('status') == 'skipped':
                    continue
                if sample.get('status') != 'passed' or not stability.finite(sample.get('elapsed_ms')) or not 0 <= sample['elapsed_ms'] <= 5000:
                    failed_targets.add(label)
            tls = attempt.get('android_tls') or {}
            if tls.get('status') != 'skipped' and not stability.tls_passed(tls):
                failed_targets.add('Android SSL')
        for label in failed_targets:
            targets[label] = targets.get(label, 0) + 1
    counts = '；'.join(f'{good}/5轮通过 **{distribution[good]}** 个' for good in sorted(distribution, reverse=True))
    details = [f'稳定性细分（{len(measured)}个实测候选）：{counts}。']
    if targets:
        labels = {'Google204': 'HTTPS 204', 'ChatGPTTrace': 'ChatGPT trace'}
        details.append('未通过目标：' + '；'.join(f'{labels.get(label, label)} **{count}** 个' for label, count in sorted(targets.items(), key=lambda x: (-x[1], x[0]))) + '。按涉及节点计，跳过不算失败，各项可能重叠。')
    return details


def write_report(report, config, path, candidate=False, website_gate=None):
    nodes = report.get('nodes', [])
    continuous = (report.get('stability_policy') or {}).get('version') in cs.VERSIONS or any((r.get('stability') or {}).get('version') in cs.VERSIONS for r in nodes)
    policy = report.get('stability_policy') or stability.settings(nodes)
    interval = policy.get('minimum_start_interval_seconds', 15)
    minimum_rounds = policy.get('minimum_rounds')
    random_idle = policy.get('random_idle_seconds_range')
    interval_text = (f'每轮结束后随机等待{random_idle[0]}～{random_idle[1]}秒' if random_idle else f'启动间隔至少{interval}秒')
    stable_label = '持续并行稳定性' if continuous else '最终间隔稳定性'
    selected_ids = set(report.get('published_node_ids', []))
    names = {n['name'] for n in config.get('proxies', [])}
    selected = [r for r in nodes if r['id'] in selected_ids and r.get('name') in names]
    by_name = {r['name']: r for r in selected}
    selected = [by_name[n['name']] for n in config.get('proxies', []) if n['name'] in by_name]
    cohort = latest_cohort(report)
    mode = report.get('publication_mode', 'full')
    title = '全量检测' if mode == 'full' else '当前订阅补测' if mode.endswith('recheck') else '按最新策略重建'
    result = '待发布候选' if candidate else '当前订阅'
    rows = ['# 节点检测报告', '',
            f'**{result}：{len(config.get("proxies", []))} 个节点。** {title}；报告更新 {clock(report.get("updated_at"))}（北京时间）。', '']
    if report.get('measurement_recovery'):
        source = report['measurement_recovery']['source_run']
        rows += [f'本次沿用[已完成的全量检测](https://github.com/hoooou/my_yml/actions/runs/{source})修复发布和分组，没有重新测速；测量时间保留。', '']
    if mode == 'full':
        rows += [f'本轮获取并去重 **{report.get("input_unique_count", 0)}** 个节点，可解析 **{report.get("parseable_count", len(nodes))}** 个。未入选节点不写入订阅。', '']
    else:
        rows += [f'最近一次上行／稳定性检测覆盖 **{len(cohort)}** 个节点；其中 **{sum(r["id"] in selected_ids for r in cohort)}** 个保留在订阅。网页、TCP和下载沿用各自的原测量。', '']
        if mode == 'repair':
            rows += ['本次仅重建配置和报告，没有重新测速。', '']
    untested = report.get('untested_subscription') or {}
    if untested.get('status') == 'fetch_failed':
        rows += ['本轮“小草莓”免测订阅获取失败，未加入免测节点；检测入选节点照常发布，下一轮自动重试。', '']
    if untested.get('node_count'):
        rows += [f'另按用户要求加入 **{untested["node_count"]}** 个“小草莓”免测节点'
                 f'（新增{untested.get("added_node_count", 0)}个，重复定义共用已有节点）；'
                 '仅放入独立手动分组和v2rayN订阅，不计入任何检测通过数，也不进入综合／下载／住宅优选组。', '']
    if not report.get('early_upload_precheck_enabled'):
        rows += ['3MB上行预检前置将在下一轮全量检测启用；当前数据仍保留调整前的实际测量时间和顺序。', '']
    counts = group_counts(config)
    if counts:
        rows += [' · '.join(f'{cell(name)} **{count}**' for name, count in counts), '',
                 ('分组会重叠，不能将数量相加；全局组手动选择、默认综合优选，其他优选组自动选择，免测组手动选择。' if (report.get('group_latency_policy') or {}).get('other_group_type') == 'url-test' else '分组会重叠，不能将数量相加；所有分组保持手动选择。'), '']
    if report.get('group_latency_policy'):
        rows += [('分组每5分钟自动检测HTTPS 200（claude.ai/cdn-cgi/trace）延迟，5秒超时；全局为select，默认综合优选；其他优选组为url-test，切换容差50ms，免测组无自动测速。客户端支持时可手动固定节点，不可用后可能自动切换。' if report['group_latency_policy'].get('other_group_type') == 'url-test' else '分组每5分钟自动检测HTTPS 200（claude.ai/cdn-cgi/trace）延迟，5秒超时；节点仍由你手动选择，测速不自动切换节点。'), '']
    if candidate and not (untested.get('node_count') and not selected):
        rows += [('最终发布状态以本次 Actions 的发布步骤为准。' if selected else
                  '**本轮无合格节点，保留原订阅。** 原订阅不代表通过这次页面与trace检测。'), '']
    elif candidate:
        rows += ['本轮没有经测试入选节点，仅有用户授权的免测节点；最终发布状态以本次Actions为准。', '']
    rows += ['## 测量时间', '', '| 数据 | 完成时间（北京时间） |', '|---|---|',
             f'| 全量检测批次完成（是否执行各项见阶段表） | {clock(report.get("measurements_updated_at") or report.get("updated_at"))} |']
    for key, label in (('website_recheck', '海外网页专项复测'), ('medium_speed_recheck', '5MB下载专项补测'),
                       ('upload_recheck', '上行与负载后SSL'), ('stability_recheck', stable_label)):
        if report.get(key):
            rows.append(f'| {label} | {clock(report[key].get("updated_at"))} |')
    if mode == 'full':
        for summary, key, label in (('upload_recheck', 'upload', '上行与负载后SSL'),
                                    ('stability_recheck', 'stability', stable_label)):
            if not report.get(summary):
                timestamps = [(r.get(key) or {}).get('updated_at') for r in nodes
                              if (r.get(key) or {}).get('updated_at')]
                rows.append(f'| {label} | {clock(max(timestamps)) if timestamps else "未测"} |')
    rows += ['', '## 入选节点', '',
             '| 节点 | 响应延迟 / 波动 ms | 下行 Mbps / 样本 | 上行 Mbps | 上传中204 | SSL | 稳定性 |',
             '|---|---:|---:|---:|---:|---|---|']
    if continuous:
        rows[-2] = '| 节点 | P95 / P99 / 波动 ms | 下行 Mbps / 样本 | 上行 Mbps | 上传中204 | SSL | 成功轮数 / 成功率 |'
    modern = (report.get('selection_policy') or {}).get('version') == qp.VERSION
    if modern:
        h = report.get('quality_history_summary') or {}
    for row in selected[:10] if modern else selected:
        stable = row.get('stability') or {}
        good_stable = stability.passed(stable)
        metrics = stability.core_metrics(stable) if good_stable else {}
        latency = max((x['median_ms'] for x in metrics.values()), default=None)
        jitter = max((x['jitter_ms'] for x in metrics.values()), default=None)
        upload = row.get('upload') or {}
        good_upload = upload_speed.passed(upload)
        upload_value = upload.get('observed_speed_mbps') if qp.modern(row) else upload.get('speed_mbps') if good_upload else None
        probes = [p for a in upload.get('attempts', []) for p in a.get('loaded_204', [])]
        success = cs.metrics(stable) if stable.get('version') in cs.VERSIONS else {}
        stability_text = (f'{success["passed_count"]}/{success["round_count"]} / {success["success_rate"]:.1%}' if success and good_stable else '5/5' if good_stable else '未验证／需复核')
        delay_text = (f'{number(max((x["p95_ms"] for x in metrics.values()), default=None))} / {number(max((x["p99_ms"] for x in metrics.values() if x.get("p99_ms") is not None), default=None))} / {number(jitter)}' if continuous else f'{number(latency)} / {number(jitter)}')
        rows.append(f'| {cell(row["name"].split("|")[0])} | {delay_text} | '
            f'{download(row)} | {number(upload_value, 1)} | '
            f'{sum(p.get("status") == "passed" for p in probes)}/{len(probes)} | '
            f'{"通过" if ssl_passed(row) else "未验证／需复核"} | {stability_text} |')
    if not selected:
        rows.append('| 本轮没有入选节点 | — | — | — | — | — | — |')
    if modern:
        rows += ['', f'仅展示排名靠前的最多10个节点，实际经测入选{len(selected)}个；上传速度未达标不等于普通节点淘汰。',
            f'近7天观察：跨日且覆盖昼夜的节点{h.get("multi_period_nodes", 0)}个，证据待积累{h.get("provisional_nodes", 0)}个；晚间有观测{h.get("peak_observed_nodes", 0)}个。首次执行不能声称已验证多天稳定。', '']
        change = report.get('quality_change') or {}
        if change.get('available'):
            differences = change['differences']
            rows += [f'相比上一轮：观察节点{differences["observed_nodes"]:+d}，稳定性通过{differences["passed_observations"]:+d}，结束仍未恢复{differences["unrecovered_nodes"]:+d}，跨时段证据充分{differences["multi_period_nodes"]:+d}。', '']
        else:
            rows += ['尚无同口径的上一轮结果，本轮作为稳定性新策略的起点。', '']
    explanation = ('P95／P99取Google／YouTube各自成功请求统计中较慢的一站，波动为较大的四分位距；失败由成功率和连续失败次数单独计入排名。成功样本较少时P99接近最大值，仅作参考；每站样本数见JSON。' if continuous else '延迟取最终五轮Google／YouTube中较慢的中位数，波动取较大的极差。')
    rows += ['', explanation + '下行用100MB实测速度，上行取两轮5MB较低速度；名称延迟仍用中位数。', '']
    excluded = [r for r in cohort if r['id'] not in selected_ids]
    if mode != 'full':
        rows += ['## 最近一轮未入选原因', '', '| 节点 | 原因 |', '|---|---|']
        for row in excluded:
            reasons = []
            if not upload_speed.passed(row.get('upload')):
                reasons.append(upload_failure(row))
            if row.get('post_upload_tls') and not app_tls.passed(row['post_upload_tls']):
                reasons.append('上传后SSL未通过')
            if row.get('stability') and not stability.passed(row['stability']):
                reasons.append('间隔稳定性未通过')
            cc = (row.get('exit') or {}).get('country_code')
            label = (row.get('name') or f'{COUNTRIES.get(cc, cc) or "地区未知"}（{row["id"][-4:]}）').split('|')[0]
            rows.append(f'| {cell(label)} | {"；".join(reasons) or "未满足当前综合／地区门槛"} |')
        if not excluded:
            rows.append('| 无 | 本轮候选全部保留 |')
    else:
        from latest_report import stage_table
        rows += stage_table(report, website_gate)
        if continuous:
            rows += ['', '稳定性在国内TCP通过后独立并行检测，至少观察10分钟；3MB上行速度不阻挡观察。持续检测行不是最后一道串行统计。' if modern else '稳定性在国内TCP与3MB上传通过后独立并行检测，覆盖范围大于后续下载、上行复测；持续检测行不是最后一道串行统计。']
        rows += ['', '各阶段仅检测满足前置条件的候选；同一节点可能在多项中失败，不能把失败数相加。逐网站及逐节点失败明细保存在JSON。', '']
        rows += stability_details(nodes)
    policy = report.get('website_measurement_policy') or {}
    required_targets = set(policy.get('required_websites', report.get('required_websites', [])))
    required_targets.update(policy.get('required_traces', report.get('required_traces', [])))
    rows += website_access_table(nodes if mode == 'full' else cohort, required_targets)
    rows += service_checks_table(nodes if mode == 'full' else cohort)
    if modern:
        app_checks = [r['application_quality'] for r in nodes if r.get('application_quality')]
        resources = [p for item in app_checks for p in item.get('youtube_resources', [])]
        rows += ['', f'YouTube资源诊断：检查{len(app_checks)}个节点，发现并请求{len(resources)}个资源，响应通过{sum(p.get("status") == "passed" for p in resources)}次；未发现资源记未测。普通资源失败暂不作为新增淘汰条件，TLS异常仍淘汰；未验证真实视频播放或登录后ChatGPT对话。', '']
    if modern:
        observed = [r['stability'] for r in nodes if (r.get('stability') or {}).get('version') == cs.VERSION]
        if observed:
            counts = {'100%': 0, '99%～100%': 0, '95%～99%': 0, '90%～95%': 0, '<90%': 0}
            stats = [cs.metrics(x) for x in observed]
            for x in stats:
                rate = x['success_rate']
                counts['100%' if rate == 1 else '99%～100%' if rate >= .99 else '95%～99%' if rate >= .95 else '90%～95%' if rate >= .9 else '<90%'] += 1
            rows += ['', '## 稳定性分布', '', '| 成功率区间 | 节点数 |', '|---|---:|']
            rows += [f'| {label} | {count} |' for label, count in counts.items()]
            rows += ['', f'持续轮次为多个新连接、应用TLS和连接池请求的联合结果；请求数合计{sum(x["request_count"] for x in stats)}，连接池请求失败{sum(x["reused_request_count"]-x["reused_success_count"] for x in stats)}。',
                f'末尾尚未恢复{sum(x["unrecovered_at_end"] for x in stats)}个节点；最长连续失败{max(x["maximum_consecutive_failures"] for x in stats)}轮。失败不混入成功响应P95，样本少于100不展示P99。', '']
    if 'Reddit' in required_targets and not (policy.get('confirmed_reddit_login_prompt') or report.get('confirmed_reddit_login_prompt')):
        rows += ['Reddit明确登录提示已改为认可通过；本表沿用旧版短正文采样，没有相应证据的旧403不会批量追认，下一轮全量按新规则实际检测。', '']
    if mode != 'full' and any(r.get('websites') for r in cohort):
        rows += ['上表只统计当前补测／重建范围的节点；未重新检测的网页沿用原测量时间。', '']
    rows += ['', '## 最新筛选流程', '', '| 顺序 | 检查 | 要求 |', '|---:|---|---|',
             ('| 1 | 双HTTPS 204 | Google与Cloudflare各三轮全部通过 |' if (report.get('precheck_policy') or {}).get('requires_both') else '| 1 | HTTPS 204 | 三轮全部通过 |'),
             '| 2 | 国内入口TCP | 国内探测点连接成功；未验证不放行 |',
             '| 3 | 3MB上行预检 | 6秒内完整上传（含建连及响应，约4Mbps下限）；失败跳过网站和下载，每分片同时一个，与下载错开 |',
             '| 4 | 1MB下载 | 6秒内完整下载，所有入选节点必过；不通过的节点不再跑网站和TLS |',
             '| 补充 | FAST API／Netflix CDN | 1MB通过后获取3个不同CDN主机，依次各下载1MB（各6秒）；仅明确证书错误影响淘汰 |',
             '| 5 | 5MB下载 | 10秒内完成才进入中速组；不通过的节点不再跑网站和TLS |',
             '| 6 | 海外网站及API／trace | 指定12站及ChatGPT API各三轮；必过trace单轮；任何网站TLS异常淘汰 |',
             '| 7 | 应用SSL | 四个域名各两次，严格校验证书链、域名和有效期 |',
             '| 8 | Cloudflare 100MB | 20秒内完成才进入高速组；5MB通过且网站、应用SSL都过才跑 |',
             '| 9 | 上行及负载 | 复用本轮3MB预检，两轮5MB各10秒、间隔20秒；上传中204全部通过 |',
             '| 10 | 负载后SSL | 再检查四个应用域名，各两次 |',
             (f'| 并行 | 持续稳定性 | TCP与3MB上传通过即启动独立观察；{"每节点至少" + str(minimum_rounds) + "轮" if minimum_rounds else "不设固定轮数"}，{interval_text}，成功率≥90%；持续到两轮上行及负载后SSL结束，再补每节点一轮；明确证书错误淘汰 |' if continuous else '| 11 | 间隔稳定性 | 五轮，轮间至少30秒，204／Google／YouTube／ChatGPT trace／Android SSL全部通过 |'), '']
    if modern:
        replacements = {'失败跳过网站和下载': '速度失败只记分级，不阻挡网站和观察',
            '上传中204全部通过': '上传中204记录负载表现，普通波动纳入分级',
            'TCP与3MB上传通过即启动独立观察': 'TCP通过即启动独立观察，至少10分钟',
            '指定12站及ChatGPT API各三轮；必过trace单轮': '指定12站及ChatGPT API各三轮，允许一次恢复的普通连接失败；trace失败可复测一次',
            '各三轮全部通过': '各三轮全部通过',
            '四个域名各两次，严格校验证书链、域名和有效期': '四域名至少两次成功握手，仅一次普通超时可补测；TLS异常不放行'}
        rows = [line for line in rows]
        for old, new in replacements.items():
            rows = [line.replace(old, new) for line in rows]
    required = (report.get('website_measurement_policy') or {}).get('required_websites', report.get('required_websites', []))
    if required:
        rows += ['必过网站：' + '、'.join(required) + '。明确的Cloudflare人机验证及Reddit明确登录提示认可可达，但不当作真实页面速度；任何已检测网站出现明确证书校验错误均不放行。', '']
    rows += ['综合组的Google／YouTube中位响应≤1500ms、最慢≤3000ms、波动≤1500ms；台湾／新加坡对应为3000／5000／3000ms，其余必过项相同。响应接近时优先上下行更均衡、重复测速更一致的节点。国内网页不用于淘汰节点，国内直连与内网DNS规则保留。', '',
             '每6小时（北京时间05/11/17/23点）重新获取全部来源检测。GitHub测速反映云端到节点的线路；国内TCP仅反映探测点可达性，不是手机移动网络带宽。SSL检查不模拟应用证书固定或登录后的会话。', '',
             '[订阅配置](https://github.com/hoooou/my_yml/blob/main/优选配置.yaml) · [当前订阅统计](https://github.com/hoooou/my_yml/blob/main/连通性报告.json)', '']
    Path(path).write_text('\n'.join(rows))
