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

FILES = ('优选配置.yaml', '连通性报告.json', '连通性报告.md')


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


def publish(root, attempts=3, files=FILES):
    root = Path(root).resolve()
    candidate = json.loads((root / '连通性报告.json').read_text())
    measured = measurement_time(candidate)
    with tempfile.TemporaryDirectory(prefix='clash-publication-') as folder:
        saved = Path(folder)
        for name in files:
            shutil.copyfile(root / name, saved / name)
        # Only generated files may be dirty in this ephemeral checkout.
        git(root, 'restore', '--', *FILES)
        if git(root, 'diff', '--quiet', check=False).returncode or git(root, 'diff', '--cached', '--quiet', check=False).returncode:
            raise RuntimeError('仓库存在非生成文件修改，拒绝更新提交基点')
        git(root, 'config', 'user.name', 'github-actions[bot]')
        git(root, 'config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com')
        for attempt in range(attempts):
            git(root, 'fetch', 'origin', 'main')
            git(root, 'checkout', '-B', 'main', 'origin/main')
            remote = json.loads((root / '连通性报告.json').read_text())
            if measurement_time(remote) > measured:
                print('远端已有更新测量，保留最新订阅', flush=True)
                return False
            for name in files:
                shutil.copyfile(saved / name, root / name)
            git(root, 'add', '--', *files)
            if git(root, 'diff', '--cached', '--quiet', check=False).returncode == 0:
                print('订阅与报告没有变化', flush=True)
                return False
            git(root, 'commit', '-m', 'Publish validated node selection')
            pushed = git(root, 'push', 'origin', 'HEAD:main', check=False)
            if pushed.returncode == 0:
                return True
            if not any(term in pushed.stderr.lower() for term in ('rejected', 'fetch first', 'non-fast-forward')):
                raise RuntimeError('Git推送失败，保留原订阅')
        raise RuntimeError('发布期间远端持续变化，保留原订阅')


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('仅支持GitHub Actions临时工作目录')
    parser = argparse.ArgumentParser()
    parser.add_argument('--report-only', action='store_true')
    args = parser.parse_args()
    if not args.report_only and not Path('.node-work/availability/selected.yaml').exists():
        print('本轮没有通过校验的新配置，保留原订阅', flush=True)
        return
    publish(Path('.'), files=FILES[1:] if args.report_only else FILES)


if __name__ == '__main__':
    main()
