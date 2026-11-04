"""Read-only Windows Event Log collector.

Uses the built-in `wevtutil.exe` (present on every supported Windows version) so no
extra driver or admin rights are needed for the Application/System logs. The
Security log is intentionally NOT read.
"""

from __future__ import annotations

import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
ALLOWED_LOGS = ("Application", "System")
MAX_EVENTS = 300
MAX_XML_BYTES = 8 * 1024 * 1024
TIMEOUT_S = 30


@dataclass
class RawEvent:
    log: str
    provider: str
    event_id: int
    level: int  # 1 critical, 2 error, 3 warning, 4 info
    time_created: datetime | None
    message: str
    data: list[str] = field(default_factory=list)
    record_id: int | None = None


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    v = value.strip().replace("Z", "+00:00")
    # wevtutil gives 7 fractional digits; older Pythons accept at most 6.
    v = re.sub(r"\.(\d{1,6})\d*", r".\1", v)
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def parse_rendered_events(xml_text: str, log: str) -> list[RawEvent]:
    """Parse `wevtutil qe /f:RenderedXml` output. Robust against garbage/truncation."""
    if not xml_text or not xml_text.strip():
        return []
    xml_text = xml_text[:MAX_XML_BYTES]
    events: list[RawEvent] = []
    try:
        root = ET.fromstring(f"<Events>{xml_text}</Events>")
        elements = root.findall("e:Event", NS)
    except ET.ParseError:
        # Corrupt or truncated output: parse event by event and skip broken ones.
        elements = []
        for chunk in xml_text.split("</Event>"):
            start = chunk.find("<Event")
            if start < 0:
                continue
            try:
                elements.append(ET.fromstring(chunk[start:] + "</Event>"))
            except ET.ParseError:
                continue
    for ev in elements[:MAX_EVENTS]:
        system = ev.find("e:System", NS)
        if system is None:
            continue
        prov = system.find("e:Provider", NS)
        eid = system.find("e:EventID", NS)
        lvl = system.find("e:Level", NS)
        tc = system.find("e:TimeCreated", NS)
        rec = system.find("e:EventRecordID", NS)
        try:
            event_id = int((eid.text or "0").strip()) if eid is not None else 0
            level = int((lvl.text or "4").strip()) if lvl is not None else 4
        except ValueError:
            continue
        msg_el = ev.find("e:RenderingInfo/e:Message", NS)
        data = [(d.text or "")[:500] for d in ev.findall("e:EventData/e:Data", NS)][:20]
        events.append(RawEvent(
            log=log,
            provider=(prov.get("Name") if prov is not None else "") or "",
            event_id=event_id,
            level=level,
            time_created=_parse_time(tc.get("SystemTime") if tc is not None else None),
            message=((msg_el.text if msg_el is not None else "") or "")[:4000],
            data=data,
            record_id=int(rec.text) if rec is not None and (rec.text or "").isdigit() else None,
        ))
    return events


def decode_tool_output(raw: bytes) -> str:
    """Decode wevtutil output: UTF-16 (with /uni:true), UTF-8, or the Windows OEM/ANSI code page.

    A wrong guess here turned German umlauts into U+FFFD on a real German Windows.
    """
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    if len(raw) >= 4 and raw[1:4:2] == b"\x00\x00" and raw[0:1] != b"\x00":
        return raw.decode("utf-16-le", errors="replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    for codec in ("oem", "mbcs", "cp1252"):  # oem/mbcs exist only on Windows
        try:
            return raw.decode(codec)
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode("utf-8", errors="replace")


def build_query(hours: int, max_level: int = 3) -> str:
    ms = max(1, min(hours, 24 * 30)) * 3600 * 1000
    levels = " or ".join(f"Level={i}" for i in range(1, max(1, min(max_level, 4)) + 1))
    return f"*[System[({levels}) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"


def collect(hours: int = 24, logs: tuple[str, ...] = ALLOWED_LOGS, max_events: int = 150) -> tuple[list[RawEvent], dict[str, str]]:
    status: dict[str, str] = {}
    out: list[RawEvent] = []
    if sys.platform != "win32":
        for log in logs:
            status[f"eventlog:{log}"] = "unavailable:not_windows"
        return out, status
    for log in logs:
        if log not in ALLOWED_LOGS:
            status[f"eventlog:{log}"] = "denied:not_allowed"
            continue
        cmd = ["wevtutil.exe", "qe", log, f"/q:{build_query(hours)}", f"/c:{max_events}", "/rd:true", "/f:RenderedXml",
               "/uni:true"]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=TIMEOUT_S, check=False,
                                  creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.TimeoutExpired) as exc:
            status[f"eventlog:{log}"] = f"error:{type(exc).__name__}"
            continue
        if proc.returncode != 0:
            status[f"eventlog:{log}"] = f"error:exit_{proc.returncode}"
            continue
        text = decode_tool_output(proc.stdout[: MAX_XML_BYTES * 2])
        parsed = parse_rendered_events(text, log)
        out.extend(parsed)
        status[f"eventlog:{log}"] = f"ok:{len(parsed)}"
    return out, status
