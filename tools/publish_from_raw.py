#!/usr/bin/env python3
"""
tools/publish_from_raw.py

Publish from IA RAW item (FSPraw) into existing target IA item (FSPneu).

Input line (separator ';' or '|', spaces optional):
  Location? ; Title ; Speaker ; Assistant ; DD.MM.YYYY ; Time (HH or HH:MM)

Behavior (strict):
- RAW selection is by Berlin date and target time.
- To prevent publishing the wrong recording when the expected RAW isn't uploaded yet,
  selection enforces a maximum allowed time difference (in minutes).
  If the closest candidate is farther than the limit -> exits with code 4 (NO_RAW_YET),
  so the workflow can queue the request.

Env:
- RAW_IA_IDENTIFIER (default: FSPraw)
- TARGET_IA_IDENTIFIER (default: FSPneu)
- IA_ACCESS_KEY, IA_SECRET_KEY (required)
- LOCATION_KEYWORDS (optional CSV)
- MAX_TIME_DIFF_MINUTES (optional int, default: 30)

Queue behavior:
- If no acceptable RAW exists for that Berlin date/time yet -> exits with code 4 ("NO_RAW_YET").

Verification behavior (added):
- After upload succeeds (HTTP 200/201), poll IA metadata until the file appears (sleep).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import unicodedata
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
    """Base error for publish pipeline."""


class NoRawYet(PublishError):
    """Raised when RAW isn't available yet for the requested Berlin date/time."""


@dataclass(frozen=True)
class ParsedLine:
    location: Optional[str]
    title: str
    speaker: str
    assistant: str
    lesson_date: date
    hour: int
    minute: int


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


def _norm_loc(s: str) -> str:
    s = s.strip().lower()
    s = (
        s.replace("ü", "u")
        .replace("ö", "o")
        .replace("ä", "a")
        .replace("ß", "ss")
        .replace("ı", "i")
    )
    return re.sub(r"\s+", " ", s)


def _location_keywords() -> Dict[str, str]:
    raw = os.getenv(
        "LOCATION_KEYWORDS",
        "Dusseldorf,Düsseldorf,Stuttgart,Reutlingen,Rheutlingen,Sachsen,Hessen",
    )
    out: Dict[str, str] = {}
    for item in raw.split(","):
        item = item.strip()
        if item:
            out[_norm_loc(item)] = item
    return out


def _split_parts(line: str) -> List[str]:
    parts = [p.strip() for p in SEP_RE.split(line.strip())]
    return [p for p in parts if p]


def _parse_date(s: str) -> date:
    m = DATE_RE.match(s.strip())
    if not m:
        raise PublishError(f"Invalid date: '{s}' (expected DD.MM.YYYY)")
    dd, mm, yy = int(m.group("d")), int(m.group("m")), int(m.group("y"))
    return date(yy, mm, dd)


def _parse_time(s: str) -> Tuple[int, int]:
    m = TIME_RE.match(s.strip())
    if not m:
        raise PublishError(f"Invalid time: '{s}' (expected HH or HH:MM)")
    h = int(m.group("h"))
    mm = int(m.group("m") or 0)
    if not (0 <= h <= 23):
        raise PublishError(f"Hour out of range: {h}")
    if not (0 <= mm <= 59):
        raise PublishError(f"Minute out of range: {mm}")
    return h, mm


def parse_line(line: str) -> ParsedLine:
    """
    Accepts:
      Location? ; Title ; Speaker ; Assistant ; DD.MM.YYYY ; HH or HH:MM
    Also accepts without location:
      Title ; Speaker ; Assistant ; DD.MM.YYYY ; HH or HH:MM
    """
    parts = _split_parts(line)
    if len(parts) < 5:
        raise PublishError("Line too short. Expected 5 or 6 fields separated by ';' or '|'.")
    hour, minute = _parse_time(parts.pop())
    lesson_dt = _parse_date(parts.pop())

    loc_map = _location_keywords()
    location: Optional[str] = None
    if len(parts) == 4 and _norm_loc(parts[0]) in loc_map:
        location = parts.pop(0)

    if len(parts) != 3:
        raise PublishError("Expected (Title; Speaker; Assistant) after optional Location.")
    title, speaker, assistant = parts[0].strip(), parts[1].strip(), parts[2].strip()
    if not assistant:
        raise PublishError("Assistenzarzt is required.")

    return ParsedLine(
        location=location,
        title=title,
        speaker=speaker,
        assistant=assistant,
        lesson_date=lesson_dt,
        hour=hour,
        minute=minute,
    )


def sanitize_filename(s: str) -> str:
    """
    UPDATED:
    - Makes filename ASCII-safe (avoids IA/UI encoding weirdness)
    - Keeps only [A-Za-z0-9 ._-]
    """
    s = s.strip()

    table = str.maketrans(
        {
            "ü": "ue",
            "Ü": "Ue",
            "ö": "oe",
            "Ö": "Oe",
            "ä": "ae",
            "Ä": "Ae",
            "ß": "ss",
            "ı": "i",
            "İ": "I",
            "ş": "s",
            "Ş": "S",
            "ğ": "g",
            "Ğ": "G",
            "ç": "c",
            "Ç": "C",
        }
    )
    s = s.translate(table)

    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))

    s = s.replace("/", "-").replace("\\", "-").replace(":", "-")
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r'[<>\"|?*\x00-\x1f]', "", s)

    s = re.sub(r"[^A-Za-z0-9 ._\-]", "", s).strip()
    return s or "recording"


def parse_raw_gmt_filename(fn: str) -> Optional[datetime]:
    m = RAW_GMT_RE.match(fn)
    if not m:
        return None
    return datetime.strptime(m.group("ymd") + m.group("hms"), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)


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
    berlin = ZoneInfo("Europe/Berlin")

    out: List[Candidate] = []
    if isinstance(files, list):
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


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw.strip())
    except ValueError as e:
        raise PublishError(f"Invalid env {name}={raw!r}, expected int") from e


def _minutes_of_day(dt: datetime) -> int:
    return dt.hour * 60 + dt.minute


def select_candidate(cands: List[Candidate], target_date: date, hour: int, minute: int) -> Candidate:
    """
    Select the best RAW candidate for the requested Berlin date/time.

    Safety:
    - Only candidates from the same Berlin calendar date are eligible.
    - If the closest candidate is farther than MAX_TIME_DIFF_MINUTES -> NoRawYet.
    """
    same_day = [c for c in cands if c.berlin_dt.date() == target_date]
    if not same_day:
        raise NoRawYet(f"No RAW candidates found for {target_date.isoformat()} (Berlin date).")

    max_diff = _env_int("MAX_TIME_DIFF_MINUTES", 30)
    target_minutes = hour * 60 + minute

    def diff_minutes(c: Candidate) -> int:
        return abs(_minutes_of_day(c.berlin_dt) - target_minutes)

    best = min(same_day, key=diff_minutes)
    best_diff = diff_minutes(best)

    top5 = sorted(same_day, key=diff_minutes)[:5]
    debug = [
        {"fn": c.filename, "berlin": c.berlin_dt.strftime("%Y-%m-%d %H:%M:%S"), "diff_min": diff_minutes(c)}
        for c in top5
    ]
    print(f"[debug] Candidate diffs (top {len(debug)}): {json.dumps(debug, ensure_ascii=False)}")

    if best_diff > max_diff:
        raise NoRawYet(
            f"Closest RAW is too far from target time: diff={best_diff}min > limit={max_diff}min "
            f"(target {hour:02d}:{minute:02d}, best {best.berlin_dt:%H:%M:%S})"
        )

    return best


def final_filename(p: ParsedLine) -> str:
    d = p.lesson_date.strftime("%d.%m.%Y")
    pieces: List[str] = []
    if p.location:
        pieces.append(p.location)
    pieces += [p.title, p.speaker, "mit", p.assistant, d]
    return sanitize_filename(" ".join(pieces) + ".m4a")


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

    print(f"[upload] PUT {identifier}/{filename} -> HTTP {r.status_code}")
    if r.status_code not in (200, 201):
        raise PublishError(f"IA upload failed for {identifier}/{filename}: HTTP {r.status_code} - {r.text[:400]}")


def wait_until_file_listed(
    session: requests.Session,
    identifier: str,
    filename: str,
    attempts: int = 6,
    sleep_s: int = 10,
) -> None:
    """
    ADDED:
    Poll IA metadata and wait until uploaded file is visible (indexing delay).
    """
    for i in range(1, attempts + 1):
        meta = ia_metadata(identifier, session)
        files = meta.get("files") or []
        names = set()
        if isinstance(files, list):
            for f in files:
                if isinstance(f, dict) and isinstance(f.get("name"), str):
                    names.add(f["name"])
        if filename in names:
            print(f"[verify] Listed on metadata: {identifier}/{filename}")
            return
        print(f"[verify] Not listed yet (attempt {i}/{attempts}) -> sleeping {sleep_s}s")
        time.sleep(sleep_s)

    raise PublishError(f"Upload completed but file not visible in metadata yet: {identifier}/{filename}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--line", required=True)
    args = ap.parse_args()

    raw_identifier = os.getenv("RAW_IA_IDENTIFIER", "FSPraw")
    target_identifier = os.getenv("TARGET_IA_IDENTIFIER", "FSPneu")

    ia_access_key = _require_env("IA_ACCESS_KEY")
    ia_secret_key = _require_env("IA_SECRET_KEY")

    p = parse_line(args.line)

    session = requests.Session()
    candidates = build_candidates(raw_identifier, session)
    chosen = select_candidate(candidates, p.lesson_date, p.hour, p.minute)

    print(f"[info] Selected RAW={chosen.filename} Berlin={chosen.berlin_dt:%Y-%m-%d %H:%M:%S}")

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

    # ADDED: verify listing with sleep/poll
    wait_until_file_listed(session, target_identifier, out_name, attempts=6, sleep_s=10)

    print(json.dumps({"ok": True, "final_filename": out_name, "raw_filename": chosen.filename}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except NoRawYet as e:
        print(f"[no-raw-yet] {e}", file=sys.stderr)
        raise SystemExit(4)
    except PublishError as e:
        print(f"[error] {e}", file=sys.stderr)
        raise SystemExit(2)
    except Exception as e:
        print(f"[error] Unexpected: {e}", file=sys.stderr)
        raise SystemExit(3)
