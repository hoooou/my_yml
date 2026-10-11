"""One compact report for the current selection; raw evidence stays in JSON."""
from datetime import datetime
import math
from pathlib import Path

import app_tls
import high_speed
import medium_speed
from select_nodes import COUNTRIES
import stability
import upload_speed


def cell(value):
    return str(value).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')


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
            ('high_speed_download', high_speed.passed, '100MB双轮'),
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
    return (not explicit_error and app_tls.passed(row.get('app_tls'))
            and app_tls.passed(row.get('post_upload_tls')))


def upload_failure(row):
    item = row.get('upload') or {}
    if not item:
        return '上行未测'
    if not upload_speed.sample_passed(item.get('precheck') or {}, upload_speed.PRECHECK_BYTES, upload_speed.PRECHECK_BUDGET):
        return '1MB上传预检未通过'
    attempts = item.get('attempts', [])
    if any(a.get('curl_exit_code') == 28 for a in attempts):
        return '5MB上传请求超时（10秒）'
    if any(p.get('status') != 'passed' or not stability.finite(p.get('elapsed_ms'))
           or not 0 <= p['elapsed_ms'] <= 5000
           for a in attempts for p in a.get('loaded_204', [])):
        return '上传期间204异常或超时'
    return '两轮上传或完整验证证据未通过'


def write_report(report, config, path, candidate=False, website_gate=None):
    nodes = report.get('nodes', [])
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
    if mode == 'full':
        rows += [f'本轮获取并去重 **{report.get("input_unique_count", 0)}** 个节点，可解析 **{report.get("parseable_count", len(nodes))}** 个。未入选节点不写入订阅。', '']
    else:
        rows += [f'最近一次上行／稳定性检测覆盖 **{len(cohort)}** 个节点；其中 **{sum(r["id"] in selected_ids for r in cohort)}** 个保留在订阅。网页、TCP和下载沿用各自的原测量。', '']
        if mode == 'repair':
            rows += ['本次仅重建配置和报告，没有重新测速。', '']
    if not report.get('early_upload_precheck_enabled'):
        rows += ['1MB上行预检前置将在下一轮全量检测启用；当前数据仍保留调整前的实际测量时间和顺序。', '']
    counts = group_counts(config)
    if counts:
        rows += [' · '.join(f'{cell(name)} **{count}**' for name, count in counts), '',
                 '分组会重叠，不能将数量相加；所有分组保持手动选择。', '']
    if candidate:
        rows += [('最终发布状态以本次 Actions 的发布步骤为准。' if selected else
                  '**本轮无合格节点，保留原订阅。** 原订阅不代表通过这次页面与trace检测。'), '']
    rows += ['## 测量时间', '', '| 数据 | 完成时间（北京时间） |', '|---|---|',
             f'| 原全量网页／TCP／1MB及100MB下载 | {clock(report.get("measurements_updated_at") or report.get("updated_at"))} |']
    for key, label in (('website_recheck', '海外网页专项复测'), ('medium_speed_recheck', '5MB下载专项补测'),
                       ('upload_recheck', '上行与负载后SSL'), ('stability_recheck', '最终间隔稳定性')):
        if report.get(key):
            rows.append(f'| {label} | {clock(report[key].get("updated_at"))} |')
    if mode == 'full':
        for summary, key, label in (('upload_recheck', 'upload', '上行与负载后SSL'),
                                    ('stability_recheck', 'stability', '最终间隔稳定性')):
            if not report.get(summary):
                timestamps = [(r.get(key) or {}).get('updated_at') for r in nodes
                              if (r.get(key) or {}).get('updated_at')]
                rows.append(f'| {label} | {clock(max(timestamps)) if timestamps else "未测"} |')
    rows += ['', '## 入选节点', '',
             '| 节点 | 响应延迟 / 波动 ms | 下行 Mbps / 样本 | 上行 Mbps | 上传中204 | SSL | 稳定性 |',
             '|---|---:|---:|---:|---:|---|---|']
    for row in selected:
        stable = row.get('stability') or {}
        good_stable = stability.passed(stable)
        metrics = stability.core_metrics(stable) if good_stable else {}
        latency = max((x['median_ms'] for x in metrics.values()), default=None)
        jitter = max((x['jitter_ms'] for x in metrics.values()), default=None)
        upload = row.get('upload') or {}
        good_upload = upload_speed.passed(upload)
        probes = [p for a in upload.get('attempts', []) for p in a.get('loaded_204', [])]
        rows.append(f'| {cell(row["name"].split("|")[0])} | {number(latency)} / {number(jitter)} | '
            f'{download(row)} | {number(upload.get("speed_mbps"), 1) if good_upload else "—"} | '
            f'{sum(p.get("status") == "passed" for p in probes)}/{len(probes)} | '
            f'{"通过" if ssl_passed(row) else "未验证／需复核"} | {"5/5" if good_stable else "未验证／需复核"} |')
    if not selected:
        rows.append('| 本轮没有入选节点 | — | — | — | — | — | — |')
    rows += ['', '延迟取最终五轮Google／YouTube中较慢的中位数，波动取较大的极差；下行优先双100MB较低速度，上行取两轮5MB较低速度。名称中的住宅和纯净度仍保留在订阅里。', '',
             '## 最近一轮未入选原因', '']
    excluded = [r for r in cohort if r['id'] not in selected_ids]
    if mode != 'full':
        rows += ['| 节点 | 原因 |', '|---|---|']
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
        rows += ['| 检查阶段 | 通过 | 未通过／需复核 | 未测／跳过 |', '|---|---:|---:|---:|']
        if website_gate:
            measured = [r for r in nodes if r.get('websites')]
            good = sum(website_gate(r) for r in measured)
            rows.append(f'| 12站＋Claude trace | {good} | {len(measured)-good} | {len(nodes)-len(measured)} |')
        for key, label, validator in (
                ('precheck', '204三轮', lambda x: x.get('status') == 'passed'),
                ('entry', '国内入口TCP', lambda x: x.get('status') == 'passed'),
                ('upload_precheck', '1MB上行预检', lambda x: upload_speed.sample_passed(x, upload_speed.PRECHECK_BYTES, upload_speed.PRECHECK_BUDGET)),
                ('app_tls', '应用SSL', app_tls.passed),
                ('download', '1MB下载', lambda x: x.get('status') == 'passed'),
                ('medium_speed_download', '5MB下载（中速组）', medium_speed.passed),
                ('high_speed_download', '双100MB下载（高速组）', high_speed.passed),
                ('upload', '两轮上行及上传中204', upload_speed.passed),
                ('post_upload_tls', '上传后SSL', app_tls.passed),
                ('stability', '五轮间隔稳定性', stability.passed)):
            items = [r.get(key) or {} for r in nodes]
            good = sum(validator(x) for x in items)
            untested = sum(x.get('status', 'missing') in ('missing', 'skipped', 'unknown', 'not_candidate') for x in items)
            rows.append(f'| {label} | {good} | {len(items)-good-untested} | {untested} |')
        rows += ['', '各阶段仅检测满足前置条件的候选；同一节点可能在多项中失败，不能把失败数相加。逐网站及逐节点失败明细保存在JSON。']
    rows += ['', '## 最新筛选流程', '', '| 顺序 | 检查 | 要求 |', '|---:|---|---|',
             '| 1 | HTTPS 204 | 三轮全部通过 |',
             '| 2 | 国内入口TCP | 国内探测点连接成功；未验证不放行 |',
             '| 3 | 1MB上行预检 | 6秒内完整上传；失败跳过网站和下载，每分片同时一个，与下载错开 |',
             '| 4 | 海外网站及trace | 指定12站各三轮；Claude仅测trace |',
             '| 5 | 应用SSL | 四个域名各两次，严格校验证书链、域名和有效期 |',
             '| 6 | 1MB下载 | 6秒内完整下载，所有入选节点必过 |',
             '| 7 | 5MB下载 | 10秒内完成才进入中速组 |',
             '| 8 | 双100MB下载 | Cloudflare和DataPacket各20秒内完成才进入高速组 |',
             '| 9 | 上行及负载 | 复用本轮1MB预检，两轮5MB各10秒、间隔20秒；上传中204全部通过 |',
             '| 10 | 负载后SSL | 再检查四个应用域名，各两次 |',
             '| 11 | 间隔稳定性 | 五轮，轮间至少30秒，204／Google／YouTube／ChatGPT trace／Android SSL全部通过 |', '']
    required = (report.get('website_measurement_policy') or {}).get('required_websites', report.get('required_websites', []))
    if required:
        rows += ['必过网站：' + '、'.join(required) + '。明确的Cloudflare人机验证认可可达，但不当作真实页面速度；任何已检测网站出现明确证书校验错误均不放行。', '']
    rows += ['综合组的Google／YouTube中位响应≤1500ms、最慢≤3000ms、波动≤1500ms；台湾／新加坡对应为3000／5000／3000ms，其余必过项相同。响应接近时优先上下行更均衡、重复测速更一致的节点。国内网页不用于淘汰节点，国内直连与公司DNS规则保留。', '',
             '每天北京时间08:00重新获取全部来源检测。GitHub测速反映云端到节点的线路；国内TCP仅反映探测点可达性，不是手机移动网络带宽。SSL检查不模拟应用证书固定或登录后的会话。', '',
             '[订阅配置](https://github.com/hoooou/my_yml/blob/main/优选配置.yaml) · [完整测量明细](https://github.com/hoooou/my_yml/blob/main/连通性报告.json)', '']
    Path(path).write_text('\n'.join(rows))
