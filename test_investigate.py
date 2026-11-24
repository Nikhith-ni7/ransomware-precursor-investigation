import copy
import json
import unittest

from adapters import normalize, read_events
from investigate import EXERCISE, ROOT, investigate

TEMPLATES = json.loads((ROOT / "evidence/templates.json").read_text())
ISSUED = json.loads((ROOT / "evidence/issued.json").read_text())


def raw_rows():
    return [json.loads(line) for line in EXERCISE.read_text().splitlines()]


def run(rows, templates=TEMPLATES, issued=ISSUED):
    return investigate([normalize(r) for r in rows], templates, issued)


def names(report):
    return [f["finding"] for f in report["findings"]]


class ExerciseTests(unittest.TestCase):
    def test_saved_findings_reproduce_even_with_duplicate_and_reordered_delivery(self):
        rows = raw_rows()
        report = run(list(reversed(rows)) + rows)
        self.assertEqual(report, json.loads((ROOT / "evidence/findings.json").read_text()))

    def test_controls_stay_quiet(self):
        rows = [r for r in raw_rows() if r.get("EventRecordID") in (101, 102, 110, 111, 112, 113, 114, 200, 201, 301)]
        self.assertEqual(run(rows)["findings"], [])


class KerberoastingTests(unittest.TestCase):
    def burst(self):
        return [r for r in raw_rows() if r.get("EventID") == 4769 and "alex" in r["TargetUserName"]]

    def test_burst_across_two_dcs_is_combined(self):
        report = run(self.burst())
        self.assertEqual(names(report), ["Kerberoasting-like service ticket burst"])
        self.assertIn("2 DC(s)", report["findings"][0]["detail"])

    def test_aes_only_burst_is_medium(self):
        rows = [dict(r, TicketEncryptionType="0x12") for r in self.burst()]
        self.assertEqual(run(rows)["findings"][0]["severity"], "medium")

    def test_boundaries(self):
        for change in ({"TimeCreated": "2026-11-24T09:06:30Z"}, {"TargetUserName": "other"},
                       {"ServiceName": "files"}, {"ServiceName": "SQL01$"}, {"Status": "0x1b"}):
            rows = self.burst()
            rows[-1] = dict(rows[-1], **change)
            self.assertEqual(run(rows)["findings"], [], change)

    def test_one_finding_per_burst(self):
        rows = self.burst()
        extra = dict(rows[-1], EventRecordID=599, ServiceName="crm", TimeCreated="2026-11-24T09:00:40Z")
        self.assertEqual(len(run(rows + [extra])["findings"]), 1)


class CertificateTests(unittest.TestCase):
    def pair(self):
        return [r for r in raw_rows() if r.get("RequestId") == "18"]

    def test_mitigated_template_is_not_flagged(self):
        for flag in TEMPLATES["LegacyAuth"]:
            inventory = {"LegacyAuth": dict(TEMPLATES["LegacyAuth"], **{flag: False})}
            self.assertEqual(run(self.pair(), templates=inventory)["findings"], [])

    def test_unknown_identity_is_flagged_for_review(self):
        report = run(self.pair(), issued={})
        self.assertEqual(names(report), ["Issuance from a risky template (identity unverified)"])

    def test_san_in_request_attributes_is_used(self):
        rows = self.pair()
        rows[1] = dict(rows[1], Attributes="CertificateTemplate:LegacyAuth\nsan:upn=Administrator@lab.example")
        report = run(rows, issued={})
        self.assertEqual(report["findings"][0]["requested_upn"], "administrator")
        self.assertNotIn("issued_identity", report["findings"][0])

    def test_issued_to_requester_is_not_flagged(self):
        self.assertEqual(run(self.pair(), issued={"ca01.lab.example/18": "alex"})["findings"], [])


class RecoveryTests(unittest.TestCase):
    def command(self, line):
        row = {"UtcTime": "2026-11-24 10:00:00.000", "Computer": "ws01", "EventRecordID": 900,
               "Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1,
               "Image": "C:\\Windows\\System32\\x.exe", "CommandLine": line, "User": "LAB\\bob"}
        return names(run([row]))

    def test_variants_are_detected(self):
        for line in ("vssadmin delete shadows /all /quiet", "VSSADMIN.EXE Delete Shadows /For=C:",
                     "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB",
                     "wmic.exe shadowcopy delete", "wbadmin DELETE SYSTEMSTATEBACKUP -keepVersions:0",
                     "bcdedit /set {default} recoveryenabled No",
                     "powershell Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }",
                     "powershell Get-CimInstance Win32_ShadowCopy | Remove-CimInstance"):
            self.assertEqual(len(self.command(line)), 1, line)

    def test_read_only_and_restore_commands_are_ignored(self):
        for line in ("vssadmin list shadows", "vssadmin list writers", "wbadmin get versions",
                     "bcdedit /set {default} recoveryenabled yes", "wmic shadowcopy list brief"):
            self.assertEqual(self.command(line), [], line)

    def test_live_control_from_the_lab_is_benign(self):
        live = json.loads((ROOT / "evidence/live-control.json").read_text())
        row = {"UtcTime": live["utc"], "Computer": "utm-win11", "EventRecordID": live["record_id"],
               "Channel": live["channel"], "EventID": live["event_id"],
               "Image": live["image"], "CommandLine": "vssadmin list writers"}
        self.assertEqual(names(run([row])), [])


class AdapterTests(unittest.TestCase):
    def test_wazuh_and_flat_formats_normalize_the_same(self):
        flat = {"TimeCreated": "2026-11-24T09:00:03.1234567Z", "Computer": "DC01", "EventRecordID": 7,
                "EventID": 4769, "TargetUserName": "alex@LAB", "ServiceName": "SQL",
                "TicketEncryptionType": "0x17", "Status": "0x0", "IpAddress": "::ffff:10.0.0.5"}
        wazuh = {"timestamp": "2026-11-24T09:00:03.123+0000", "data": {"win": {
            "system": {"eventID": "4769", "computer": "DC01", "eventRecordID": "7",
                       "systemTime": "2026-11-24T09:00:03.1234567Z"},
            "eventdata": {"targetUserName": "alex@LAB", "serviceName": "SQL",
                          "ticketEncryptionType": "0x17", "status": "0x0", "ipAddress": "::ffff:10.0.0.5"}}}}
        a, b = normalize(flat), normalize(wazuh)
        self.assertEqual({k: v for k, v in a.items() if k != "source"},
                         {k: v for k, v in b.items() if k != "source"})
        self.assertEqual((a["account"], a["ip"], a["service"]), ("alex", "10.0.0.5", "sql"))

    def test_bad_lines_are_skipped_not_fatal(self):
        import tempfile, pathlib
        path = pathlib.Path(tempfile.mkdtemp()) / "x.jsonl"
        path.write_text('{"EventID": 4769}\nnot json\n' + json.dumps(raw_rows()[0]) + "\n")
        events, skipped = read_events([path])
        self.assertEqual((len(events), skipped), (1, 2))


class LinkTests(unittest.TestCase):
    def test_stages_link_through_requester_and_issued_identity(self):
        report = run(raw_rows())
        self.assertEqual(len(report["linked"]), 1)
        self.assertEqual(report["linked"][0]["linked_by"], ["alex", "lab-admin"])

    def test_without_the_certificate_the_stages_do_not_link(self):
        rows = [r for r in raw_rows() if r.get("RequestId") != "18"]
        self.assertEqual(run(rows)["linked"], [])


if __name__ == "__main__":
    unittest.main()
