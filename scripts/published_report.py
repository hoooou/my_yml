"""Small repository summaries; raw evidence is loaded only by automation."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ARTIFACT = 'full-test-report'
FILENAME = 'full-test-report.published.json'


def repository_summary(report, raw_bytes, run_id):
    if not str(run_id).isdigit():
        raise ValueError('原始报告附件必须关联明确的Actions运行')
    summary = copy.deepcopy({k: v for k, v in report.items() if k != 'nodes'})
    selected = set(report.get('published_node_ids') or [])
    fields = ('id', 'name', 'server', 'port', 'protocol', 'sources', 'exit')
    summary['nodes'] = [{k: copy.deepcopy(row[k]) for k in fields if k in row}
                        for row in report.get('nodes', []) if row['id'] in selected]
    summary['report_kind'] = 'published_summary'
    summary['raw_record_count'] = len(report.get('nodes', []))
    summary['raw_evidence'] = {'run_id': str(run_id), 'artifact': ARTIFACT,
        'filename': FILENAME, 'sha256': hashlib.sha256(raw_bytes).hexdigest(), 'retention_days': 7}
    return summary


def load_report(value, cache_root=None):
    """Never interpret stripped summaries as complete probe evidence."""
    report = json.loads(Path(value).read_text()) if not isinstance(value, dict) else value
    if report.get('report_kind') != 'published_summary':
        return report
    evidence = report['raw_evidence']
    run_id = str(evidence['run_id'])
    if (not run_id.isdigit() or evidence['artifact'] != ARTIFACT or evidence['filename'] != FILENAME
            or not re.fullmatch('[0-9a-f]{64}', evidence['sha256'])):
        raise ValueError('原始报告附件引用无效')
    root = Path(cache_root or '.node-work/published-report-cache') / run_id
    path = root / FILENAME
    if not path.exists():
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as folder:
            result = subprocess.run(['gh', 'run', 'download', run_id, '-R',
                os.environ.get('GITHUB_REPOSITORY', 'hoooou/my_yml'), '-n', ARTIFACT, '-D', folder],
                capture_output=True, text=True, timeout=180)
            downloaded = Path(folder) / FILENAME
            if result.returncode or not downloaded.exists():
                raise RuntimeError('原始证据附件未能读取或已过7天保留期；不能将摘要当作检测证据')
            downloaded.replace(path)
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != evidence['sha256']:
        raise ValueError('原始证据附件校验失败')
    data = json.loads(raw)
    if (str(data.get('source_run')) != run_id
            or data.get('published_node_ids') != report.get('published_node_ids')
            or data.get('measurements_updated_at') != report.get('measurements_updated_at')):
        raise ValueError('原始证据附件与当前订阅不匹配')
    return data
