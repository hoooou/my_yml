import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import stability_diagnostics as d
from test_stability import evidence


class DiagnosticCandidatesTests(unittest.TestCase):
    def test_failed_nodes_resolved_from_history_and_sample_is_bounded(self):
        rows = []
        nodes = []
        for i in range(18):
            row = {'id': 'n-' + str(i), 'name': 'old-' + str(i), 'stability': evidence()}
            if i < 12:
                row['stability']['status'] = 'failed'
                row['stability']['attempts'][1]['sites']['Google204']['status'] = 'failed'
            rows.append(row)
            nodes.append({'name': row['name'], 'type': 'http' if i < 15 else 'vless'})
        current = copy.deepcopy(rows)
        for row in current[:12]:
            row.pop('name')
        selected, mapping = d.candidates({'nodes': current}, [({'proxies': nodes}, {'nodes': rows})])
        self.assertEqual(len(selected), 12)
        self.assertEqual([k for _, k in selected].count('collapsed_HTTPS'), 8)
        self.assertEqual(mapping[selected[0][0]['id']]['name'], selected[0][0]['id'])


if __name__ == '__main__':
    unittest.main()
