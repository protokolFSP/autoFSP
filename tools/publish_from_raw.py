# tools/publish_from_raw.py
#!/usr/bin/env python3
"""
Publish from IA RAW item (FSPraw) into existing target IA item (FSPneu).

Input line (separator: ';' or '|', spaces optional):
  Location? ; Title ; Speaker ; Assistant? ; DD.MM.YYYY ; Time?(HH or HH:MM)

Examples:
  Düsseldorf; Burn-Out Syndrome; Dr Sümeyra; Dr Ekrem; 23.02.2026; 9:39
  Burn-Out Syndrome; Dr Sümeyra; 23.02.2026; 11
  Stuttgart; Burn-Out Syndrome; Dr Sümeyra; 23.02.2026; 11

Rules:
- Location is optional, but if present it should be the FIRST field (before Title).
- Location is recognized by a keyword list (default + env override LOCATION_KEYWORDS).
- Time is optional; if provided it is used only for selecting the RAW file (Berlin time).
- Final filename (time is NEVER included):
    "<Location> <Title> <Speaker> [mit <Assistant>] DD.MM.YYYY.m4a"
  If Location is missing:
    "<Title> <Speaker> [mit <Assistant>] DD.MM.YYYY.m4a"

RAW selection:
- Fetch https://archive.org/metadata/FSPraw
- Consider files matching: GMTYYYYMMDD-HHMMSS_*.m4a (UTC)
- Convert UTC -> Europe/Berlin; match Berlin date
- If time provided: choose candidate with minimum absolute minute difference (seconds tiebreak)
- If time not provided: deterministic Nth-earliest per date using STATE_PATH (.publish_state.json)

Upload:
- Downloads RAW from https://archive.org/download/FSPraw/<filename>
- Uploads to https://s3.us.archive.org/FSPneu/<final_filename> (overwrite allowed)
- Sets stable item-level metadata (audio, language, creator, date).

Env:
- IA_ACCESS_KEY, IA_SECRET_KEY (required)
- RAW_IA_IDENTIFIER (default: FSPraw)
- TARGET_IA_IDENTIFIER (default: FSPneu)
- STATE_PATH (default: .publish_state.json)
- LOCATION_KEYWORDS (optional, comma-separated)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import date, datetime, timezone
from tempfile import NamedTemporaryFile
from typing import Any, Dict, List, Optional, Tuple

import requests

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore


IA_META_BASE = "https://archive.org/metadata"
IA_DOWNLOAD_BASE = "https://archive.org/download"
IA_S3_BASE = "https://s3.us.archive.org"

RAW_GMT_RE = re.compile(r"^GMT(?P<ymd>\d{8})-(?P<hms>\d{6})_.*\.m4a$", re.IGNORECASE)
SEP_RE = re.compile(r"\s*[;|]\s*")
TIME_RE = re.compile(r"^(?P<h>\d{1,2})(:(?P<m>\d{2}))?$")
DATE_RE = re.compile(r"^(?P<d>\d{1,2})\.(?P<m>\d{1,2})\.(?P<y>\d{4})$")


class PublishError(RuntimeError):
    """Publish failure."""


@dataclass(frozen=True)
class ParsedLine:
    location: Optional[str]
    title: str
    speaker: str
    assistant: Optional[str]
    lesson_date: date
    hour: Optional[int]
    minute: Optional[int]


@dataclass(frozen=True)
class Candidate:
    filename: str
    utc_dt: datetime
    berlin_dt: datetime


def _require_env(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise PublishError(f"Missing required env var: {name}")
    return v


def _safe_write_json(path: str, data: Dict[str, Any]) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def _load_json(path: str, default: Dict[str, Any]) -> Dict[str, Any]:
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else default


def _split_parts(line: str) -> List[str]:
    parts = [p.strip() for p in SEP_RE.split(line.strip())]
    return [p for p in parts if p]


def _norm_loc(s: str) -> str:
    s = s.strip().lower()
    s = (
        s.replace("ü", "u")
        .replace("ö", "o")
        .replace("ä", "a")
        .replace("ß", "ss")
        .replace("ı", "i")
    )
    s = re.sub(r"\s+", " ", s)
    return s


def _location_keywords() -> Dict[str, str]:
    raw = os.getenv(
        "LOCATION_KEYWORDS",
        "Dusseldorf,Düsseldorf,Stuttgart,Reutlingen,Rheutlingen,Sachsen,Hessen",
    )
    out: Dict[str, str] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        out[_norm_loc(item)] = item
    return out


def _parse_date(s: str) -> date:
    m = DATE_RE.match(s.strip())
    if not m:
        raise PublishError(f"Invalid date: '{s}' (expected DD.MM.YYYY)")
    dd, mm, yy = int(m.group("d")), int(m.group("m")), int(m.group("y"))
    try:
        return date(yy, mm, dd)
    except Exception:
        raise PublishError(f"Invalid date: '{s}' (expected DD.MM.YYYY)")


def _parse_time(s: str) -> Tuple[int, int]:
    m = TIME_RE.match(s.strip())
    if not m:
        raise PublishError(f"Invalid time: '{s}' (expected HH or HH:MM)")
    h = int(m.group("h"))
    mm = int(m.group("m") or 0)
    if h < 0 or h > 23:
        raise PublishError(f"Hour out of range (0-23): {h}")
    if mm < 0 or mm > 59:
        raise PublishError(f"Minute out of range (0-59): {mm}")
    return h, mm


def parse_line(line: str) -> ParsedLine:
    """
    Accepts:
      Location? ; Title ; Speaker ; Assistant? ; DD.MM.YYYY ; Time?(HH or HH:MM)
    """
    parts = _split_parts(line)
    if len(parts) < 3:
        raise PublishError(
            "Invalid line. Use ';' or '|' separator:\n"
            "Location? ; Title ; Speaker ; Assistant? ; DD.MM.YYYY ; Time?(HH or HH:MM)"
        )

    hour: Optional[int] = None
    minute: Optional[int] = None

    # Optional time at end
    if TIME_RE.match(parts[-1]):
        hour, minute = _parse_time(parts.pop())

    # Date required at end
    if not parts or not DATE_RE.match(parts[-1]):
        got = parts[-1] if parts else ""
        raise PublishError(f"Invalid date: '{got}' (expected DD.MM.YYYY)")
    lesson_dt = _parse_date(parts.pop())

    if len(parts) < 2:
        raise PublishError("Need at least Title and Speaker before date.")

    loc_map = _location_keywords()
    location: Optional[str] = None

    # Location as first field if recognized
    if parts and _norm_loc(parts[0]) in loc_map:
        location = parts.pop(0)

    # Now: Title, Speaker, optional Assistant
    title = parts[0]
    speaker = parts[1]
    extras = parts[2:]

    assistant: Optional[str] = None
    if len(extras) == 1:
        assistant = extras[0].strip() or None
    elif len(extras) > 1:
        raise PublishError(
            "Too many fields. Expected:\n"
            "Location? ; Title ; Speaker ; Assistant? ; DD.MM.YYYY ; Time?"
        )

    return ParsedLine(
        location=location.strip() if isinstance(location, str) and location.strip() else None,
        title=title.strip(),
        speaker=speaker.strip(),
        assistant=assistant.strip() if isinstance(assistant, str) and assistant.strip() else None,
        lesson_date=lesson_dt,
        hour=hour,
        minute=minute,
    )


def sanitize_filename(s: str) -> str:
    s = s.strip()
    s = s.replace("/", "-").replace("\\", "-").replace(":", "-")
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r"[<>\"|?*\x00-\x1f]", "", s)
    return s


def parse_raw_gmt_filename(fn: str) -> Optional[datetime]:
    m = RAW_GMT_RE.match(fn)
    if not m:
        return None
    try:
        return datetime.strptime(m.group("ymd") + m.group("hms"), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def ia_metadata(identifier: str, session: requests.Session) -> Dict[str, Any]:
    r = session.get(f"{IA_META_BASE}/{identifier}", timeout=60)
    if r.status_code != 200:
        raise PublishError(f"IA metadata fetch failed for {identifier}: HTTP {r.status_code} - {r.text[:300]}")
    return r.json()


def build_candidates(raw_identifier: str, session: requests.Session) -> List[Candidate]:
    if ZoneInfo is None:
        raise PublishError("zoneinfo not available (unexpected on GitHub Actions).")

    meta = ia_metadata(raw_identifier, session)
    files = meta.get("files") or []
    if not isinstance(files, list):
        raise PublishError("IA metadata 'files' is not a list.")

    berlin = ZoneInfo("Europe/Berlin")
    out: List[Candidate] = []
    for f in files:
        if not isinstance(f, dict):
            continue
        name = f.get("name")
        if not isinstance(name, str) or not name.lower().endswith(".m4a"):
            continue
        utc_dt = parse_raw_gmt_filename(name)
        if not utc_dt:
            continue
        out.append(Candidate(filename=name, utc_dt=utc_dt, berlin_dt=utc_dt.astimezone(berlin)))
    return out


def select_candidate(
    cands: List[Candidate],
    target_date: date,
    hour: Optional[int],
    minute: Optional[int],
    publish_state: Dict[str, Any],
) -> Tuple[Candidate, Dict[str, Any]]:
    same_day = [c for c in cands if c.berlin_dt.date() == target_date]
    if not same_day:
        raise PublishError(f"No RAW candidates found for {target_date.isoformat()} (Berlin date).")

    same_day_sorted = sorted(same_day, key=lambda c: (c.berlin_dt.hour, c.berlin_dt.minute, c.berlin_dt.second))

    if hour is not None:
        target_minutes = hour * 60 + (minute or 0)

        def score(c: Candidate) -> Tuple[int, int]:
            cand_minutes = c.berlin_dt.hour * 60 + c.berlin_dt.minute
            return (abs(cand_minutes - target_minutes), abs(c.berlin_dt.second))

        return sorted(same_day_sorted, key=score)[0], publish_state

    # No time -> deterministic Nth earliest
    key = target_date.isoformat()
    entry = publish_state.get(key)
    if not isinstance(entry, dict):
        entry = {"used": 0}
    used = entry.get("used", 0)
    if not isinstance(used, int) or used < 0:
        used = 0
    if used >= len(same_day_sorted):
        times = ", ".join(f"{c.berlin_dt:%H:%M}" for c in same_day_sorted)
        raise PublishError(f"Time missing and no remaining candidates for {key}. times=[{times}] used={used}")
    chosen = same_day_sorted[used]
    entry["used"] = used + 1
    publish_state[key] = entry
    return chosen, publish_state


def final_filename(p: ParsedLine) -> str:
    d = p.lesson_date.strftime("%d.%m.%Y")
    pieces: List[str] = []
    if p.location:
        pieces.append(p.location)  # city first
    pieces += [p.title, p.speaker]
    if p.assistant:
        pieces += ["mit", p.assistant]
    name = " ".join(pieces + [d]) + ".m4a"
    return sanitize_filename(name)


def download_raw_to_file(raw_identifier: str, filename: str, session: requests.Session) -> str:
    url = f"{IA_DOWNLOAD_BASE}/{raw_identifier}/{filename}"
    r = session.get(url, timeout=240, stream=True)
    if r.status_code != 200:
        raise PublishError(f"RAW download failed: HTTP {r.status_code} - {r.text[:300]}")

    tmp = NamedTemporaryFile(delete=False, suffix=".m4a")
    try:
        for chunk in r.iter_content(chunk_size=1024 * 1024):
            if chunk:
                tmp.write(chunk)
        tmp.flush()
        return tmp.name
    finally:
        tmp.close()


def ia_put_with_metadata(
    session: requests.Session,
    ia_access_key: str,
    ia_secret_key: str,
    identifier: str,
    filename: str,
    file_path: str,
    metadata: Dict[str, str],
) -> None:
    url = f"{IA_S3_BASE}/{identifier}/{filename}"
    headers = {
        "Authorization": f"LOW {ia_access_key}:{ia_secret_key}",
        "Content-Type": "audio/mp4",
        "x-archive-auto-make-bucket": "1",
    }
    for k, v in metadata.items():
        headers[f"x-archive-meta-{k}"] = v

    with open(file_path, "rb") as f:
        r = session.put(url, data=f, headers=headers, timeout=600)
    if r.status_code not in (200, 201):
        raise PublishError(f"IA upload failed for {identifier}/{filename}: HTTP {r.status_code} - {r.text[:400]}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--line", required=True)
    args = ap.parse_args()

    raw_identifier = os.getenv("RAW_IA_IDENTIFIER", "FSPraw")
    target_identifier = os.getenv("TARGET_IA_IDENTIFIER", "FSPneu")
    state_path = os.getenv("STATE_PATH", ".publish_state.json")

    ia_access_key = _require_env("IA_ACCESS_KEY")
    ia_secret_key = _require_env("IA_SECRET_KEY")

    p = parse_line(args.line)

    session = requests.Session()
    publish_state = _load_json(state_path, default={})

    candidates = build_candidates(raw_identifier, session)
    chosen, publish_state = select_candidate(candidates, p.lesson_date, p.hour, p.minute, publish_state)

    print(
        f"[info] Selected RAW={chosen.filename} "
        f"UTC={chosen.utc_dt:%Y-%m-%d %H:%M:%S} "
        f"Berlin={chosen.berlin_dt:%Y-%m-%d %H:%M:%S}"
    )

    out_name = final_filename(p)
    tmp_path = download_raw_to_file(raw_identifier, chosen.filename, session)

    meta = {
        "mediatype": "audio",
        "title": "FSPneu Upload",
        "language": "deu",
        "creator": "ProtokolFSP",
        "date": p.lesson_date.isoformat(),
    }

    ia_put_with_metadata(
        session=session,
        ia_access_key=ia_access_key,
        ia_secret_key=ia_secret_key,
        identifier=target_identifier,
        filename=out_name,
        file_path=tmp_path,
        metadata=meta,
    )

    _safe_write_json(state_path, publish_state)

    print(json.dumps(
        {
            "ok": True,
            "raw_identifier": raw_identifier,
            "raw_filename": chosen.filename,
            "target_identifier": target_identifier,
            "final_filename": out_name,
            "time_used_for_selection": f"{p.hour:02d}:{(p.minute or 0):02d}" if p.hour is not None else None,
            "location": p.location,
            "state_path": state_path,
        },
        ensure_ascii=False,
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PublishError as e:
        print(f"[error] {e}", file=sys.stderr)
        raise SystemExit(2)
    except Exception as e:
        print(f"[error] Unexpected: {e}", file=sys.stderr)
        raise SystemExit(3)
