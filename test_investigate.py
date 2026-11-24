import json
import unittest
from investigate import ROOT, investigate


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.events = [json.loads(s) for s in (ROOT / 'evidence/replay.jsonl').read_text().splitlines()]
        self.templates = json.loads((ROOT / 'evidence/templates.json').read_text())

    def test_expected_evidence_including_controls_and_duplicate_delivery(self):
        findings = investigate(list(reversed(self.events)) + self.events, self.templates)
        self.assertEqual([row['records'] for row in findings], [[103,104,105,106],[202,203],[302],[303]])
        self.assertEqual(findings, json.loads((ROOT / 'evidence/findings.json').read_text()))

    def test_window_and_account_boundaries(self):
        burst = self.events[2:6]
        for change in ({'utc':'2026-11-24T09:06:30Z'}, {'account':'other'}, {'service':'files'}):
            self.assertEqual(investigate(burst[:-1] + [dict(burst[-1], **change)], self.templates), [])

    def test_template_mitigation_and_other_ca(self):
        pair = self.events[8:10]
        for flag in self.templates['LegacyAuth']:
            inventory = {'LegacyAuth': dict(self.templates['LegacyAuth'], **{flag:False})}
            self.assertEqual(investigate(pair, inventory), [])
        self.assertEqual(investigate([pair[0],dict(pair[1],host='other-ca')], self.templates), [])

    def test_live_writer_query_is_benign(self):
        live = json.loads((ROOT / 'evidence/live-control.json').read_text())
        self.assertEqual(live['exit_code'], 0)
        event = dict(live, host='UTM', record=live['record_id'], event=live['event_id'])
        self.assertEqual(investigate([event], {}), [])
