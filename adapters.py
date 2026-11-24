"""Read Windows events from the formats this lab produces and normalize them.

Supported input, one JSON object per line (auto-detected per line):
- Wazuh alerts.json rows from the Windows agent (data.win.system / data.win.eventdata)
- Flat Windows event JSON: Get-WinEvent exports (tools/Export-LabEvents.ps1) and public
  recorded datasets such as OTRF Security-Datasets, with EventID, Computer/Hostname and
  EventData fields at the top level

Every event comes out as a dict with: utc (aware datetime), host, record, event_id, source,
plus the fields the detections use, all with consistent names.
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

TIME_KEYS = ("UtcTime", "TimeCreated", "@timestamp", "EventTime", "timestamp", "utc")
HOST_KEYS = ("Computer", "Hostname", "host", "computer")
RECORD_KEYS = ("EventRecordID", "RecordNumber", "record_id", "record")
TEMPLATE = re.compile(r"CertificateTemplate:\s*([^\s\r\n]+)", re.IGNORECASE)
SAN_UPN = re.compile(r"san:[^\r\n]*upn=([^&\s\r\n]+)", re.IGNORECASE)


class FormatError(ValueError):
    pass


def first(row, keys, default=None):
    for key in keys:
        if row.get(key) not in (None, ""):
            return row[key]
    return default


def parse_time(value):
    if isinstance(value, dict):  # Get-WinEvent ConvertTo-Json on PowerShell 5 can nest dates
        value = value.get("DateTime") or value.get("value")
    if not isinstance(value, str) or not value.strip():
        raise FormatError("event has no timestamp")
    text = value.strip().replace(" ", "T", 1) if re.match(r"\d{4}-\d\d-\d\d \d", value.strip()) else value.strip()
    text = text.replace("Z", "+00:00")
    # Python accepts at most 6 fractional digits; Windows writes 7.
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    parsed = datetime.fromisoformat(text)
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def from_wazuh(row):
    win = row["data"]["win"]
    system, data = win.get("system", {}), win.get("eventdata", {})
    flat = {key[:1].upper() + key[1:]: value for key, value in data.items()}
    flat.update({
        "EventID": system.get("eventID"),
        "Computer": system.get("computer") or row.get("agent", {}).get("name"),
        "EventRecordID": system.get("eventRecordID"),
        "Channel": system.get("channel"),
        "TimeCreated": system.get("systemTime") or row.get("timestamp"),
    })
    return flat, "wazuh"


def account(value):
    """'LAB\\alex', 'alex@LAB.LOCAL' and 'alex' all become 'alex'."""
    if not isinstance(value, str):
        return ""
    value = value.strip().split("\\")[-1].split("@")[0]
    return value.casefold()


def normalize(row):
    if not isinstance(row, dict):
        raise FormatError("expected a JSON object")
    if isinstance(row.get("data"), dict) and isinstance(row["data"].get("win"), dict):
        flat, source = from_wazuh(row)
    else:
        flat, source = row, "windows_json"
    try:
        event_id = int(flat.get("EventID") if flat.get("EventID") is not None else flat.get("event_id"))
    except (TypeError, ValueError) as error:
        raise FormatError("event has no EventID") from error
    host = str(first(flat, HOST_KEYS, "unknown")).lower()
    record = first(flat, RECORD_KEYS)
    event = {
        "utc": parse_time(first(flat, TIME_KEYS)),
        "host": host,
        "record": int(record) if str(record).isdigit() else record,
        "event_id": event_id,
        "source": source,
    }
    if event_id == 4769:
        event.update(
            account=account(flat.get("TargetUserName")),
            service=str(flat.get("ServiceName", "")).casefold(),
            encryption=str(flat.get("TicketEncryptionType", "")).lower(),
            status=str(flat.get("Status", "")).lower(),
            ip=str(flat.get("IpAddress", "")).replace("::ffff:", ""),
        )
    elif event_id in (4886, 4887):
        attributes = str(flat.get("Attributes", ""))
        template = TEMPLATE.search(attributes)
        upn = SAN_UPN.search(attributes)
        event.update(
            request_id=str(flat.get("RequestId", "")),
            requester=account(flat.get("Requester")),
            template=template.group(1) if template else str(flat.get("CertificateTemplate", "")),
            requested_upn=account(upn.group(1)) if upn else "",
            subject=str(flat.get("Subject", "")),
        )
    elif event_id == 1 and "sysmon" in str(flat.get("Channel", "sysmon")).lower():
        event.update(
            image=str(flat.get("Image", "")),
            command_line=str(flat.get("CommandLine", "")),
            parent_image=str(flat.get("ParentImage", "")),
            user=account(flat.get("User")),
            logon_id=str(flat.get("LogonId", "")),
        )
    return event


def read_events(paths):
    events, skipped = [], 0
    for path in paths:
        for number, line in enumerate(Path(path).read_text(encoding="utf-8-sig").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                events.append(normalize(json.loads(line)))
            except (FormatError, json.JSONDecodeError, KeyError) as error:
                skipped += 1
                if skipped <= 5:
                    print(f"skipped {path}:{number}: {error}", file=sys.stderr)
    return events, skipped
