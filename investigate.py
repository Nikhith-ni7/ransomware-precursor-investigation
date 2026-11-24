"""Detect ransomware precursor activity in Windows events and link the stages.

Python 3.10+, standard library only.

Usage:
  python3 investigate.py                                   # synthetic exercise
  python3 investigate.py events.jsonl wazuh-alerts.json    # your own exports
  python3 investigate.py --templates evidence/templates.json --issued evidence/issued.json ...
"""

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from adapters import read_events

ROOT = Path(__file__).resolve().parent
EXERCISE = ROOT / "evidence" / "exercise.jsonl"
RC4 = "0x17"
BURST_WINDOW = timedelta(minutes=5)
BURST_SERVICES = 4
LINK_WINDOW = timedelta(hours=2)
RISKY_FLAGS = ("broad_enrollment", "requester_supplies_subject", "authentication_eku",
               "no_approval_or_signatures")

# Recovery-inhibition command lines. Matched case-insensitively; dash or slash flags.
RECOVERY_PATTERNS = [
    ("Shadow-copy deletion", re.compile(r"vssadmin(\.exe)?\W.*\bdelete\s+shadows", re.I)),
    ("Shadow storage shrink", re.compile(r"vssadmin(\.exe)?\W.*\bresize\s+shadowstorage", re.I)),
    ("Shadow-copy deletion (WMIC)", re.compile(r"wmic(\.exe)?\W.*\bshadowcopy\b.*\bdelete", re.I)),
    ("Shadow-copy deletion (PowerShell)",
     re.compile(r"win32_shadowcopy.*(\.delete\(|remove-ciminstance|remove-wmiobject)", re.I)),
    ("Backup catalog deletion", re.compile(r"wbadmin(\.exe)?\W.*\bdelete\s+(catalog|systemstatebackup|backup)", re.I)),
    ("Recovery disabled", re.compile(r"bcdedit(\.exe)?\W.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", re.I)),
]


def kerberoasting(events):
    """Many service tickets for user service accounts from one requester and address.

    Requests are combined across domain controllers. Machine accounts and krbtgt are
    excluded. RC4 tickets raise the severity because they crack fastest offline.
    """
    findings = []
    groups = defaultdict(list)
    for e in events:
        if (e["event_id"] == 4769 and e["status"] in ("0x0", "0") and e["service"]
                and not e["service"].endswith("$") and e["service"] != "krbtgt"
                and not e["account"].endswith("$")):
            groups[e["account"], e["ip"]].append(e)
    for (user, ip), rows in groups.items():
        rows.sort(key=lambda e: e["utc"])
        start = 0
        reported_until = None
        for end, row in enumerate(rows):
            while row["utc"] - rows[start]["utc"] > BURST_WINDOW:
                start += 1
            window = rows[start:end + 1]
            services = {e["service"] for e in window}
            if len(services) >= BURST_SERVICES and (reported_until is None or window[0]["utc"] > reported_until):
                rc4 = any(e["encryption"] == RC4 for e in window)
                findings.append(finding(
                    row, "Kerberoasting-like service ticket burst", "credential_access", "high" if rc4 else "medium",
                    window, account=user,
                    detail=f"{len(services)} services in {int((row['utc'] - window[0]['utc']).total_seconds())} s from {ip}"
                           f" via {len({e['host'] for e in window})} DC(s); "
                           + ("RC4 tickets requested" if rc4 else "AES only"),
                    ip=ip))
                reported_until = row["utc"]
    return findings


def certificate_abuse(events, templates, issued):
    """ESC1-style issuance: a risky template issued a certificate for someone other than the requester."""
    findings = []
    requests = {}
    for e in events:
        if e["event_id"] == 4886:
            requests[e["host"], e["request_id"]] = e
    for e in events:
        if e["event_id"] != 4887:
            continue
        request = requests.get((e["host"], e["request_id"]))
        template = templates.get(e["template"], {})
        if not all(template.get(flag) for flag in RISKY_FLAGS):
            continue
        requester = e["requester"] or (request or {}).get("requester", "")
        identity = issued.get(f"{e['host']}/{e['request_id']}")
        requested = e["requested_upn"] or (request or {}).get("requested_upn", "")
        rows = [r for r in (request, e) if r]
        if identity and identity != requester:
            findings.append(finding(e, "ESC1-like certificate issuance", "privilege_escalation", "high", rows, account=requester,
                                    detail=f"template {e['template']} issued a certificate for {identity}",
                                    issued_identity=identity))
        elif not identity:
            findings.append(finding(e, "Issuance from a risky template (identity unverified)",
                                    "privilege_escalation", "medium", rows,
                                    account=requester,
                                    detail=f"template {e['template']}; decode the issued certificate's SAN to confirm",
                                    requested_upn=requested))
    return findings


def recovery_inhibition(events):
    findings = []
    for e in events:
        if e["event_id"] != 1 or not e.get("command_line"):
            continue
        for name, pattern in RECOVERY_PATTERNS:
            if pattern.search(e["command_line"]):
                findings.append(finding(e, f"{name} attempt", "impact", "high", [e], account=e.get("user", ""),
                                        detail=e["image"].replace("/", "\\").rsplit("\\", 1)[-1].lower()))
                break
    return findings


def finding(event, name, stage, severity, rows, account="", detail="", **extra):
    return {
        "utc": event["utc"].strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": event["host"],
        "finding": name,
        "stage": stage,
        "severity": severity,
        "account": account,
        "detail": detail,
        "records": [r["record"] for r in sorted(rows, key=lambda r: r["utc"])],
        **extra,
    }


def link_stages(findings):
    """Group findings that share an account (requester, issued identity or process user)
    within LINK_WINDOW. These are hypotheses for the analyst, not proof of one actor."""
    def identities(f):
        return {i for i in (f["account"], f.get("issued_identity", "")) if i}

    ordered = sorted(findings, key=lambda f: f["utc"])
    chains, used = [], set()
    for i, first in enumerate(ordered):
        if i in used:
            continue
        chain, names = [i], identities(first)
        for j in range(i + 1, len(ordered)):
            later = ordered[j]
            gap = (_time(later) - _time(ordered[chain[-1]]))
            if gap <= LINK_WINDOW and names & identities(later):
                chain.append(j)
                names |= identities(later)
        if len({ordered[k]["stage"] for k in chain}) > 1:
            used.update(chain)
            chains.append({
                "hypothesis": "Same actor across stages (unconfirmed)",
                "linked_by": sorted(names),
                "stages": [f"{ordered[k]['utc']} {ordered[k]['host']}: {ordered[k]['finding']}" for k in chain],
                "to_confirm": "Join logon sessions (4624 logon ID to Sysmon LogonId) and certificate "
                              "authentication (4768 with certificate) before treating this as one intrusion.",
            })
    return chains


def _time(f):
    return datetime.strptime(f["utc"], "%Y-%m-%dT%H:%M:%SZ")


def investigate(events, templates, issued=None):
    seen, unique = set(), []
    for e in sorted(events, key=lambda e: e["utc"]):
        key = (e["host"], e["record"], e["event_id"])
        if key not in seen:
            seen.add(key)
            unique.append(e)
    findings = kerberoasting(unique) + certificate_abuse(unique, templates, issued or {}) + recovery_inhibition(unique)
    findings.sort(key=lambda f: (f["utc"], f["host"]))
    return {"findings": findings, "linked": link_stages(findings)}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("events", nargs="*", type=Path, default=[EXERCISE])
    parser.add_argument("--templates", type=Path, default=ROOT / "evidence" / "templates.json",
                        help="template inventory (see README)")
    parser.add_argument("--issued", type=Path, default=ROOT / "evidence" / "issued.json",
                        help="issued identities decoded from certificates, keyed 'ca-host/request-id'")
    args = parser.parse_args()
    events, skipped = read_events(args.events)
    templates = json.loads(args.templates.read_text()) if args.templates.exists() else {}
    issued = json.loads(args.issued.read_text()) if args.issued.exists() else {}
    report = investigate(events, templates, issued)
    report["input"] = {"events": len(events), "skipped": skipped}
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
