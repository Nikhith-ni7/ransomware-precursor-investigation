"""Replay projected Windows evidence. Python 3.10+, standard library only."""
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def timestamp(event):
    return datetime.fromisoformat(event["utc"].replace("Z", "+00:00"))


def investigate(events, templates):
    findings = []
    windows = defaultdict(deque)
    requests = {}
    seen = set()
    for e in sorted(events, key=timestamp):
        key = (e["host"], e["record"])
        if key in seen:
            continue
        seen.add(key)
        now = timestamp(e)
        evidence = [e["record"]]
        if e["event"] == 4769 and e["status"] == "success" and e["cipher"] == "RC4":
            window = windows[e["host"], e["account"], e["ip"]]
            while window and now - timestamp(window[0]) > timedelta(minutes=5):
                window.popleft()
            before = {row["service"] for row in window}
            window.append(e)
            if len(before) >= 4 or len(before | {e["service"]}) < 4:
                continue
            rule = "Service-ticket burst"
            evidence = [row["record"] for row in window]
        elif e["event"] == 4886:
            requests[e["host"], e["request_id"]] = e
            continue
        elif e["event"] == 4887:
            request = requests.get((e["host"], e["request_id"]))
            template = templates.get(e["template"], {})
            if not request or request["template"] != e["template"]:
                continue
            if not all(template.get(flag) for flag in (
                "broad_enrollment", "requester_supplies_subject", "authentication_eku",
                "no_approval_or_signatures"
            )):
                continue
            if request["account"].casefold() == e["issued_identity"].casefold():
                continue
            rule = "ESC1-like certificate issuance"
            evidence = [request["record"], e["record"]]
        elif e["event"] == 1:
            pair = (e["image"].lower(), e["operation"])
            rule = {("vssadmin.exe", "delete shadows"): "Shadow-copy deletion attempt",
                    ("wbadmin.exe", "delete catalog"): "Backup catalog deletion attempt"}.get(pair)
            if not rule:
                continue
        else:
            continue
        findings.append(dict(utc=e["utc"], host=e["host"], finding=rule, records=evidence))
    return findings


if __name__ == "__main__":
    events = [json.loads(line) for line in (ROOT / "evidence/replay.jsonl").read_text().splitlines()]
    templates = json.loads((ROOT / "evidence/templates.json").read_text())
    print(json.dumps(investigate(events, templates), indent=2))
