#!/usr/bin/env python3
"""
Publish from IA RAW item (FSPraw) into an existing target IA item (FSPneu).

Input line format (single line, '|' separated):
  Title | Speaker | Assistant(optional) | DD.MM.YYYY | Hour(optional, Berlin time)

Selection:
- List RAW files from https://archive.org/metadata/FSPraw
- Parse filenames like: GMTYYYYMMDD-HHMMSS_Recording.m4a (UTC)
- Convert to Europe/Berlin, match date; if hour given pick closest
- If hour NOT given:
    - Use a repo state file (STATE_PATH, default .publish_state.json)
    - For that date, pick Nth earliest candidate where N = used_count
    - Increment used_count after successful upload

Overwrite:
- Uploads to TARGET_IA_IDENTIFIER using final filename; overwrite is allowed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import date, datetime, timezone
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


class PublishError(RuntimeError):
    """Raised for publish failures that should fail the workflow."""


@dataclass(frozen=True)
class ParsedLine:
    title: str
    speaker: str
    assistant: Optional[str]
    lesson_date: date
    hour: Optional[int]


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
    if not isinstance(data, dict):
        return default
    return data


def parse_line(line: str) -> ParsedLine:
    parts = [p.strip() for p in line.split("|")]
    parts = [p for p in parts if p != ""]
    if len(parts) < 4:
        raise PublishError(
            "Line parse failed. Expected at least 4 parts: "
            "Title | Speaker | Assistant(optional) | DD.MM.YYYY | Hour(optional)"
        )

    maybe_hour = parts[-1]
    maybe_date = parts[-2] if len(parts) >= 2 else ""

    hour: Optional[int] = None
    if re.fullmatch(r"\d{1,2}", maybe_hour) and maybe_date.count(".") == 2:
        hour = int(maybe_hour)
        if hour < 0 or hour > 23:
            raise PublishError(f"Hour out of range: {hour}")
        date_str = maybe_date
        core = parts[:-2]
    else:
        date_str = parts[-1] if parts[-1].count(".") == 2 else maybe_date
        core = parts[:-1]

    if date_str.count(".") != 2:
        raise PublishError(f"Date missing/invalid. Got: '{date_str}' (expected DD.MM.YYYY)")

    try:
        dd, mm, yyyy = [int(x) for x in date_str.split(".")]
        lesson_dt = date(yyyy, mm, dd)
    except Exception:
        raise PublishError(f"Date invalid: '{date_str}' (expected DD.MM.YYYY)")

    if len(core) < 2:
        raise PublishError("Need at least Title and Speaker before date.")
    title = core[0]
    speaker = core[1]
    assistant = core[2] if len(core) >= 3 else None
    if assistant == "":
        assistant = None

    return ParsedLine(
        title=title,
        speaker=speaker,
        assistant=assistant,
        lesson_date=lesson_dt,
        hour=hour,
    )


def parse_raw_gmt_filename(fn: str) -> Optional[datetime]:
    m = RAW_GMT_RE.match(fn)
    if not m:
        return None
    ymd = m.group("ymd")
    hms = m.group("hms")
    try:
        return datetime.strptime(ymd + hms, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except Exception:
        return None


@dataclass(frozen=True)
class Candidate:
    filename: str
    utc_dt: datetime
    berlin_dt: datetime


def ia_metadata(identifier: str, session: requests.Session) -> Dict[str, Any]:
    r = session.get(f"{IA_META_BASE}/{identifier}", timeout=60)
    if r.status_code != 200:
        raise PublishError(f"IA metadata fetch failed for {identifier}: HTTP {r.status_code} - {r.text[:300]}")
    return r.json()


def build_candidates(raw_identifier: str, session: requests.Session) -> List[Candidate]:
    if ZoneInfo is None:
        raise PublishError("zoneinfo not available in this Python runtime.")
    meta = ia_metadata(raw_identifier, session)
    files = meta.get("files") or []
    if not isinstance(files, list):
        raise PublishError("IA metadata shape unexpected: 'files' is not a list.")

    berlin = ZoneInfo("Europe/Berlin")
    out: List[Candidate] = []
    for f in files:
        if not isinstance(f, dict):
            continue
        name = f.get("name")
        if not isinstance(name, str):
            continue
        if not name.lower().endswith(".m4a"):
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
    publish_state: Dict[str, Any],
) -> Tuple[Candidate, Dict[str, Any]]:
    same_day = [c for c in cands if c.berlin_dt.date() == target_date]
    if not same_day:
        raise PublishError(f"No RAW candidates found for {target_date.isoformat()} (Berlin date).")

    same_day_sorted = sorted(same_day, key=lambda c: (c.berlin_dt.hour, c.berlin_dt.minute, c.berlin_dt.second))

    if hour is not None:
        def score(c: Candidate) -> Tuple[int, int]:
            return (abs(c.berlin_dt.hour - hour), abs(c.berlin_dt.minute))
        chosen = sorted(same_day_sorted, key=score)[0]
        return chosen, publish_state

    key = target_date.isoformat()
    entry = publish_state.get(key)
    if not isinstance(entry, dict):
        entry = {"used": 0}
    used = entry.get("used", 0)
    if not isinstance(used, int) or used < 0:
        used = 0

    if used >= len(same_day_sorted):
        times = ", ".join(f"{c.berlin_dt:%H:%M}" for c in same_day_sorted)
        raise PublishError(
            f"Hour not provided, but all RAW recordings for {target_date.strftime('%d.%m.%Y')} are already consumed. "
            f"candidates={len(same_day_sorted)} used={used} times=[{times}]"
        )

    chosen = same_day_sorted[used]
    entry["used"] = used + 1
    publish_state[key] = entry
    return chosen, publish_state


def final_filename(p: ParsedLine) -> str:
    d = p.lesson_date.strftime("%d.%m.%Y")
    if p.assistant:
        return f"{p.title} {p.speaker} mit {p.assistant} {d}.m4a"
    return f"{p.title} {p.speaker} {d}.m4a"


def final_title_meta(p: ParsedLine) -> str:
    d = p.lesson_date.strftime("%d.%m.%Y")
    if p.assistant:
        return f"{p.title} – {p.speaker} (mit {p.assistant}) – {d}"
    return f"{p.title} – {p.speaker} – {d}"


def download_raw(raw_identifier: str, filename: str, session: requests.Session) -> bytes:
    url = f"{IA_DOWNLOAD_BASE}/{raw_identifier}/{filename}"
    r = session.get(url, timeout=180)
    if r.status_code != 200:
        raise PublishError(f"RAW download failed: HTTP {r.status_code} - {r.text[:300]}")
    return r.content


def ia_put_with_metadata(
    session: requests.Session,
    ia_access_key: str,
    ia_secret_key: str,
    identifier: str,
    filename: str,
    content: bytes,
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

    r = session.put(url, data=content, headers=headers, timeout=240)
    if r.status_code not in (200, 201):
        raise PublishError(f"IA upload failed for {identifier}/{filename}: HTTP {r.status_code} - {r.text[:400]}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--line", required=True, help="Single line input from Google Form")
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

    chosen, publish_state = select_candidate(candidates, p.lesson_date, p.hour, publish_state)

    print(
        f"[info] Selected RAW: {chosen.filename} "
        f"(UTC {chosen.utc_dt:%Y-%m-%d %H:%M:%S}, Berlin {chosen.berlin_dt:%Y-%m-%d %H:%M})"
    )

    content = download_raw(raw_identifier, chosen.filename, session)

    out_name = final_filename(p)
    meta = {
        "mediatype": "audio",
        "title": final_title_meta(p),
        "date": p.lesson_date.isoformat(),
        "language": "deu",
        "creator": "ProtokolFSP",
    }

    ia_put_with_metadata(
        session=session,
        ia_access_key=ia_access_key,
        ia_secret_key=ia_secret_key,
        identifier=target_identifier,
        filename=out_name,
        content=content,
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
            "hour_provided": p.hour is not None,
            "publish_state_path": state_path,
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
