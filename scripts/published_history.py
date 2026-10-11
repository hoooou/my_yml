"""Recover two published snapshots as candidates, without carrying measurements."""
import copy
import hashlib
import json
import subprocess

import yaml
import select_nodes as s


def collect(nodes, metadata):
    combined = list(nodes)
    info = copy.deepcopy(metadata)
    seen = {n['name'] for n in nodes}
    stats = {'snapshot_limit': 2, 'refs': [], 'added_count': 0, 'added_ids': [],
             'measurement_reuse': False, 'status': 'ok'}
    try:
        refs = subprocess.check_output(['git', 'log', '-2', '--format=%H', '--', '优选配置.yaml'],
                                       text=True, stderr=subprocess.DEVNULL, timeout=10).splitlines()
        for ref in refs:
            config = yaml.safe_load(subprocess.check_output(['git', 'show', ref + ':优选配置.yaml'],
                                                           text=True, stderr=subprocess.DEVNULL, timeout=10))
            report = json.loads(subprocess.check_output(['git', 'show', ref + ':连通性报告.json'],
                                                       text=True, stderr=subprocess.DEVNULL, timeout=10))
            by_name = {n['name']: n for n in config.get('proxies') or []}
            selected = set(report.get('published_node_ids') or [])
            stats['refs'].append(ref)
            for row in report.get('nodes') or []:
                if row.get('id') not in selected or row.get('name') not in by_name:
                    continue
                raw = s.canonical_node(by_name[row['name']])
                if raw is None:
                    continue
                identity = 'n-' + hashlib.sha256(json.dumps(raw, sort_keys=True, ensure_ascii=False,
                                                           default=str).encode()).hexdigest()[:12]
                if identity in seen:
                    continue
                raw['name'] = identity
                combined.append(raw); seen.add(identity)
                info[identity] = {'sources': row.get('sources') or [],
                                  'candidate_origin': 'published_history', 'history_ref': ref}
                stats['added_ids'].append(identity)
    except (subprocess.SubprocessError, ValueError, KeyError, TypeError, yaml.YAMLError):
        stats['status'] = 'history_unavailable_or_incomplete'
    stats['added_count'] = len(stats['added_ids'])
    return combined, info, stats
