"""Keep the latest attempt visible even when the subscription is retained."""
from collections import Counter
import json
import os
from pathlib import Path
import tempfile

import app_tls
import high_speed
import medium_speed
import service_probes
import stability
import upload_speed

START = '<!-- latest-detection:start -->'
END = '<!-- latest-detection:end -->'
REPORT_FILES = ('最新检测.json', 'README.md')


def readme_fragment(text):
    if START not in text or END not in text:
        return None
    return text.split(START, 1)[1].split(END, 1)[0].strip()


def replace_fragment(text, fragment):
    block = START + '\n' + fragment.strip() + '\n' + END
    if START in text and END in text:
        before, rest = text.split(START, 1)
        return before + block + rest.split(END, 1)[1]
    return text.rstrip() + '\n\n' + block + '\n'


def counts(stage_id, label, items, validator, fallback):
    row = {'id': stage_id, 'label': label, 'passed': 0, 'failed': 0,
           'unverified': 0, 'skipped': 0, 'reason_counts': {}}
    reasons = Counter()
    for item in items:
        item = item or {}
        status = item.get('status', 'missing')
        if not item or status in ('missing', 'skipped', 'not_candidate') or (
                stage_id == 'tcp' and status == 'unknown' and item.get('attempts') == 0):
            outcome = 'skipped'
        elif validator(item):
            outcome = 'passed'
        elif status in ('unknown', 'unavailable', 'incomplete'):
            outcome = 'unverified'
        else:
            outcome = 'failed'
        row[outcome] += 1
        if outcome != 'passed':
            reason = item.get('reason')
            if not reason and outcome in ('failed', 'unverified'):
                if stage_id == 'stability':
                    import continuous_stability as cs
                    if any(cs.certificate_error(a) for a in item.get('attempts', [])):
                        reason = '明确证书校验错误'
                    elif item.get('version') in (2, 3, cs.VERSION) and cs.metrics(item)['success_rate'] < .9:
                        reason = '持续观察成功率低于90%'
                    else:
                        reason = '稳定性原始证据或检查条件未满足，详见逐轮记录'
                else:
                    attempts = item.get('attempts') or []
                    errors = sorted({a.get('reason') or a.get('error_type') or a.get('status', '异常')
                                     for a in attempts if a.get('status') not in ('passed', 'skipped')})
                    reason = '／'.join(errors[:2]) if errors else '已检测但未满足通过条件，详见原始证据'
            reasons[(outcome, reason or fallback)] += 1
    row['measured'] = row['passed'] + row['failed'] + row['unverified']
    row['reason_counts'] = [{'status': status, 'reason': reason, 'count': n}
                            for (status, reason), n in reasons.most_common()]
    return row


def stage_summary(report, website_gate=None):
    if website_gate is None:
        from availability import required_websites_passed
        website_gate = required_websites_passed
    nodes = report.get('nodes', [])
    rows = []
    def add(stage_id, label, key, validator, fallback):
        rows.append(counts(stage_id, label, (r.get(key) for r in nodes), validator, fallback))
    passed = lambda x: x.get('status') == 'passed'
    sources = report.get('sources') or []
    rows.append(counts('sources', '订阅来源获取', sources, lambda x: x.get('status') == 'ok', '来源获取异常'))
    parseable = report.get('parseable_count', len(nodes))
    inputs = report.get('input_unique_count', len(nodes))
    rows.append({'id': 'parse', 'label': '去重后配置解析／字符检查', 'measured': inputs,
        'passed': parseable, 'failed': max(0, inputs - parseable), 'unverified': 0, 'skipped': 0,
        'reason_counts': ([{'status': 'failed', 'reason': '内核不支持或非法控制字符；不写入订阅',
                           'count': inputs - parseable}] if inputs > parseable else [])})
    dual_204 = any((r.get('precheck') or {}).get('version') == 2 for r in nodes)
    add('204', '双204各三轮（均必过）' if dual_204 else '204三轮', 'precheck', passed, '未进行204检测')
    if dual_204:
        for label in ('Google204', 'Cloudflare204'):
            rows.append(counts('204_' + label, label + '三轮',
                ((r.get('precheck') or {}).get('targets', {}).get(label) for r in nodes), passed, '未进行该目标204检测'))
    add('tcp', '国内入口TCP', 'entry', passed, '204未通过或UDP不适用；未提交TCP探测')
    if any(r.get('website_tls') for r in nodes):
        add('website_tls', '网站TLS异常硬筛选', 'website_tls', passed, '网站未测，未检查网站TLS')
    add('upload_precheck', '3MB上行预检', 'upload_precheck',
        lambda x: upload_speed.sample_passed(x, upload_speed.PRECHECK_BYTES, upload_speed.PRECHECK_BUDGET),
        '国内TCP未通过，未进行3MB上行预检')
    items = []
    for record in nodes:
        sites = record.get('websites') or {}
        if sites:
            accepted = website_gate(record)
            items.append({'status': 'passed' if accepted else 'failed',
                          'reason': '必过网页/API或trace未全部通过；各站原因见下表'})
        else:
            items.append({'status': 'skipped', 'reason': '国内TCP或3MB上传未通过，未进行网站检测'})
    api_tested = any('ChatGPTAPI' in (r.get('websites') or {}) for r in nodes)
    rows.append(counts('websites', '12站＋ChatGPT API＋必过trace' if api_tested else '12站＋Claude trace', items, passed, '未进行网站检测'))
    add('app_tls', '应用SSL', 'app_tls', app_tls.passed, '必过网站未通过，未进行应用SSL检查')
    add('download', '1MB下载', 'download', passed, '网站或应用SSL未通过，未进行1MB下载')
    fast = [(r.get('service_checks') or {}).get('targets', {}).get('FAST') or {} for r in nodes]
    rows.append(counts('fast_api', 'FAST API', (x.get('api') for x in fast), passed,
                       '1MB未通过，未请求FAST API'))
    for index in range(service_probes.FAST_TARGET_COUNT):
        samples = []
        for item in fast:
            downloads = item.get('downloads', [item['download']] if item.get('download') else [])
            samples.append(downloads[index] if len(downloads) > index else {
                'status': 'skipped', 'reason': 'FAST未返回该有效目标或前置1MB未通过'})
        rows.append(counts(f'fast_cdn_{index + 1}', f'FAST CDN {index + 1}（1MB）', samples, passed, '未测'))
    add('medium', '5MB下载（中速组）', 'medium_speed_download', medium_speed.passed, '1MB未通过，未进行5MB下载')
    for index, url in enumerate(high_speed.URLS):
        samples = []
        for r in nodes:
            attempts = (r.get('high_speed_download') or {}).get('attempts') or []
            samples.append(attempts[index] if len(attempts) > index else {})
        rows.append(counts(f'high_{index + 1}', ('Cloudflare' if index == 0 else 'DataPacket') + ' 100MB',
                           samples, lambda x, url=url: high_speed.sample_passed(x, url), '1MB未通过，未进行100MB下载'))
    add('high', '双100MB下载（高速组）', 'high_speed_download', high_speed.passed, '未完成双目标100MB检测')
    add('upload', '两轮上行及上传中204', 'upload', upload_speed.passed, '未进入合格候选池，未进行两轮上行检测')
    for index in range(upload_speed.ROUNDS):
        samples = []
        for record in nodes:
            attempts = (record.get('upload') or {}).get('attempts') or []
            samples.append(attempts[index] if len(attempts) > index else {})
        rows.append(counts(f'upload_{index + 1}', f'5MB上行第{index + 1}轮', samples,
                           upload_speed.sample_passed, '未进入合格池，未执行该轮5MB上传'))
    add('post_upload_tls', '上传后SSL', 'post_upload_tls', app_tls.passed, '未进行两轮上行，未进行上传后SSL检查')
    add('stability', '持续并行稳定性', 'stability', stability.passed, '国内TCP或3MB上行未通过，未开始观察')
    exits, types, reputations = [], [], []
    for record in nodes:
        exit_info = record.get('exit') or {}
        exits.append({'status': 'passed' if exit_info.get('exit_ip') and exit_info.get('country_code') else
                      'unknown' if record.get('websites') else 'skipped',
                      'reason': '出口IP／地区未确认或未进入网站阶段'})
        ip_type = record.get('ip_type') or {}
        types.append(ip_type if exit_info else {'status': 'skipped', 'reason': '出口未确认，不查询IP类型'})
        reputation = record.get('ip_reputation') or {}
        if reputation.get('reason') in ('not_eligible', 'not_configured'):
            reputation = {**reputation, 'status': 'skipped', 'reason':
                '未入选候选池，不查询住宅／纯净度' if reputation['reason'] == 'not_eligible' else '未配置IPAPI_IS_KEY，保持未知'}
        reputations.append(reputation)
    rows.append(counts('exit', '出口地区确认', exits, passed, '出口未确认'))
    rows.append(counts('ip_type', 'IP类型查询', types,
                       lambda x: x.get('status') == 'success' and type(x.get('hosting')) is bool, 'IP类型未确认'))
    rows.append(counts('ip_reputation', '住宅／纯净度查询', reputations,
                       lambda x: x.get('status') == 'success', '接口不可用，住宅／纯净度保持未知'))
    validation = report.get('configuration_validation')
    rows.append(counts('config_validation', '最终配置校验', [{'status':
        'passed' if validation in ('passed', 'historical_verified') else 'failed' if validation == 'failed' else 'skipped',
        'reason': '没有合格候选，保留旧订阅' if not report.get('selected_node_count', report.get('published_node_count'))
                  else '未完成最终内核校验，不能声称配置已发布'}], passed, '未校验'))
    return rows


def stage_table(report, website_gate=None):
    from detection_report import cell
    rows = ['## 每个环节的检测记录', '',
            '| 检查阶段 | 实测 | 通过 | 未通过 | 未验证 | 未测／跳过 | 主要失败或跳过原因 |',
            '|---|---:|---:|---:|---:|---:|---|']
    for stage in stage_summary(report, website_gate):
        reason = '；'.join(f'{x["count"]}：{x["reason"]}' for x in stage['reason_counts'][:2]) or '全部通过'
        rows.append(f'| {stage["label"]} | {stage["measured"]} | {stage["passed"]} | {stage["failed"]} | '
                    f'{stage["unverified"]} | {stage["skipped"]} | {cell(reason)} |')
    rows += ['', '未验证与真实失败分开；未测不计失败。TCP不适用于UDP，未提交的TCP探测列为跳过。FAST、5MB与100MB用于补测或分组，普通失败不等于综合池淘汰。稳定性独立并行，阶段计数不能相加。详细原因计数保存在最新检测JSON，逐次原始请求在本次Actions附件。', '']
    return rows


def write_latest(report, config, root=Path('.'), website_gate=None, candidate=False, validation=None):
    """Publish compact metadata and a README section, preserving manual prose."""
    from detection_report import write_report, latest_cohort, website_access_summary
    root = Path(root)
    summary = {k: v for k, v in report.items() if k != 'nodes'}
    summary['website_access_summary'] = website_access_summary(latest_cohort(report))
    validation = validation or report.get('configuration_validation') or 'not_checked'
    summary.update(stage_summary=stage_summary({**report, 'configuration_validation': validation}, website_gate),
                   record_count=len(report.get('nodes', [])),
                   source_run=report.get('source_run') or os.environ.get('GITHUB_RUN_ID'),
                   source_run_attempt=report.get('source_run_attempt') or os.environ.get('GITHUB_RUN_ATTEMPT'),
                   configuration_validation=validation,
                   report_kind='latest_attempt',
                   selected_node_count=len(config.get('proxies', [])))
    # Raw, unselected node evidence is kept in the run artifact, not duplicated in Git.
    summary['raw_records_retention_days'] = 7
    retained = root / '连通性报告.json'
    if (not config.get('proxies') or validation == 'failed') and retained.exists():
        try:
            old = json.loads(retained.read_text())
            summary['retained_subscription'] = {'node_count': old.get('published_node_count'),
                'measurements_updated_at': old.get('measurements_updated_at') or old.get('updated_at')}
        except ValueError:
            pass
    (root / '最新检测.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    with tempfile.TemporaryDirectory() as folder:
        rendered = Path(folder) / 'report.md'
        write_report({**report, 'configuration_validation': summary['configuration_validation']}, config,
                     rendered, candidate=candidate, website_gate=website_gate)
        fragment = rendered.read_text()
    # Rules and the pipeline are documented once, in the manual section.
    fragment = fragment.split('\n## 最新筛选流程', 1)[0].rstrip()
    if summary.get('retained_subscription'):
        old = summary['retained_subscription']
        fragment += f'\n\n当前继续保留原订阅的 **{old["node_count"]}** 个节点，原测量时间 **{old["measurements_updated_at"]}**；这些节点未被本轮重新验证为合格。\n'
    fragment = '\n'.join('#' + line if line.startswith('#') else line for line in fragment.splitlines())
    if summary['source_run']:
        fragment += f'\n\n[本轮Actions及原始测量附件](https://github.com/hoooou/my_yml/actions/runs/{summary["source_run"]})。原始附件保留7天。\n'
    readme = root / 'README.md'
    manual = readme.read_text() if readme.exists() else '# Clash 节点优选\n'
    readme.write_text(replace_fragment(manual, fragment))
    return summary


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--summary', action='store_true')
    args = parser.parse_args()
    if args.summary:
        data = json.loads(Path('最新检测.json').read_text()) if Path('最新检测.json').exists() else {}
        if os.environ.get('GITHUB_RUN_ID') and str(data.get('source_run')) != os.environ['GITHUB_RUN_ID']:
            print('本次尚未生成完整检测报告；参阅本次运行日志，原订阅保留。')
        else:
            print(readme_fragment(Path('README.md').read_text()) or '本轮摘要未生成。')
