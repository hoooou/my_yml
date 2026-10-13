"""Publish generated files on current main, without rebasing generated text.

This entry point runs only in an ephemeral GitHub Actions checkout. The local
library tests use disposable repositories; the shared user checkout is untouched.
"""
from datetime import datetime
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from latest_report import REPORT_FILES, readme_fragment, replace_fragment
from published_report import repository_summary, FILENAME

FILES = ('优选配置.yaml', 'v2rayN.txt', '连通性报告.json', *REPORT_FILES)
REPORT_COMPACT_THRESHOLD = 25 * 1024 * 1024


def compact_report(path):
    """Keep all raw evidence, omitting indentation in the Git copy only."""
    if not path.exists() or path.stat().st_size <= REPORT_COMPACT_THRESHOLD:
        return
    original_size = path.stat().st_size
    data = json.loads(path.read_text())
    with path.open('w', encoding='utf-8') as handle:
        json.dump(data, handle, ensure_ascii=False, separators=(',', ':'))
        handle.write('\n')
    if path.stat().st_size >= 100 * 1024 * 1024:
        raise RuntimeError('完整报告压缩格式后仍超过GitHub单文件上限，保留原订阅；原始证据在Actions附件')
    print(f'完整报告保留全部数据，仅移除缩进：{original_size / 1048576:.1f} → '
          f'{path.stat().st_size / 1048576:.1f} MiB', flush=True)


def retryable_push(stderr):
    message = stderr.lower()
    return any(term in message for term in ('fetch first', 'non-fast-forward',
        'updates were rejected because the remote contains work', 'cannot lock ref'))


def git(root, *args, check=True):
    result = subprocess.run(['git', *args], cwd=root, capture_output=True, text=True)
    if check and result.returncode:
        raise RuntimeError('Git发布步骤失败：' + args[0])
    return result


def measurement_time(report):
    value = datetime.fromisoformat(report.get('measurements_updated_at') or report['updated_at'])
    if value.tzinfo is None:
        raise ValueError('测量时间必须有时区')
    return value


def validated_same_run_rebuild(candidate, remote_latest):
    recovery = candidate.get('measurement_recovery') or {}
    remote_recovery = remote_latest.get('measurement_recovery') or {}
    source = recovery.get('source_run')
    remote_source = remote_recovery.get('source_run') or remote_latest.get('source_run')
    # A verified same-run rebuild can change policy/configuration, not measurements.
    # The source-run check remains strict even if validation made the published
    # timestamp a few seconds newer than the raw measurement artifact.
    return (source is not None and remote_source is not None and str(source) == str(remote_source)
            and recovery.get('new_probes') is False
            and candidate.get('configuration_validation') == 'passed'
            and datetime.fromisoformat(candidate['updated_at']) > datetime.fromisoformat(remote_latest['updated_at']))


def publish(root, attempts=3, files=FILES):
    root = Path(root).resolve()
    report_name = '最新检测.json' if '最新检测.json' in files else '连通性报告.json'
    candidate = json.loads((root / report_name).read_text())
    measured = measurement_time(candidate)
    with tempfile.TemporaryDirectory(prefix='clash-publication-') as folder:
        saved = Path(folder)
        for name in files:
            shutil.copyfile(root / name, saved / name)
        raw_path = saved / '连通性报告.json'
        if raw_path.exists() and (root / '.node-work/availability' / FILENAME).exists():
            raw = raw_path.read_bytes()
            report = json.loads(raw)
            summary = repository_summary(report, raw, os.environ['GITHUB_RUN_ID'])
            raw_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
        else:
            compact_report(raw_path)
        # Only generated files may be dirty in this ephemeral checkout.
        git(root, 'restore', '--', *FILES)
        if git(root, 'diff', '--quiet', check=False).returncode or git(root, 'diff', '--cached', '--quiet', check=False).returncode:
            raise RuntimeError('仓库存在非生成文件修改，拒绝更新提交基点')
        git(root, 'config', 'user.name', 'github-actions[bot]')
        git(root, 'config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com')
        for attempt in range(attempts):
            git(root, 'fetch', 'origin', 'main')
            git(root, 'checkout', '-B', 'main', 'origin/main')
            remote_reports = {name: json.loads((root / name).read_text())
                              for name in ('最新检测.json', '连通性报告.json') if (root / name).exists()}
            remote_times = [measurement_time(r) for r in remote_reports.values()]
            same_run = ('优选配置.yaml' in files and validated_same_run_rebuild(
                candidate, remote_reports.get('最新检测.json') or {}))
            if max(remote_times, default=measured) > measured and not same_run:
                print('远端已有更新测量，保留最新订阅', flush=True)
                return False
            for name in files:
                if name == 'README.md' and readme_fragment((saved / name).read_text()) is not None:
                    # Preserve documentation edits made after this run checked out main.
                    (root / name).write_text(replace_fragment((root / name).read_text(),
                                              readme_fragment((saved / name).read_text())))
                else:
                    shutil.copyfile(saved / name, root / name)
            git(root, 'add', '--', *files)
            if git(root, 'diff', '--cached', '--quiet', check=False).returncode == 0:
                print('订阅与报告没有变化', flush=True)
                return False
            git(root, 'commit', '-m', 'Publish validated node selection')
            pushed = git(root, 'push', 'origin', 'HEAD:main', check=False)
            if pushed.returncode == 0:
                return True
            if not retryable_push(pushed.stderr):
                if 'GH001' in pushed.stderr or 'exceeds GitHub' in pushed.stderr:
                    raise RuntimeError('GitHub拒绝超大文件，保留原订阅；不是远端分支冲突')
                raise RuntimeError('Git推送被拒绝（非远端分支冲突），保留原订阅')
        raise RuntimeError('发布期间远端持续变化，保留原订阅')


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('仅支持GitHub Actions临时工作目录')
    parser = argparse.ArgumentParser()
    parser.add_argument('--report-only', action='store_true')
    args = parser.parse_args()
    latest = Path('最新检测.json')
    if not latest.exists():
        print('没有本轮检测摘要；保留原订阅和原报告', flush=True)
        return
    latest_data = json.loads(latest.read_text())
    if os.environ.get('GITHUB_RUN_ID') and str(latest_data.get('source_run')) != os.environ['GITHUB_RUN_ID']:
        print('本次运行尚未生成新报告，保留原订阅及原记录', flush=True)
        return
    checked = latest_data.get('configuration_validation') == 'passed'
    ready = Path('.node-work/availability/selected.yaml').exists() and checked
    report_only = args.report_only or not ready
    if report_only:
        print('只发布最新检测记录；原订阅及其测量不变', flush=True)
    publish(Path('.'), files=REPORT_FILES if report_only else FILES)


if __name__ == '__main__':
    main()
