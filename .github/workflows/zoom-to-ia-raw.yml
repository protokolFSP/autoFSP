#!/usr/bin/env python3
"""
Sync Zoom cloud recording M4A files into Internet Archive RAW item (FSPraw).

Key points:
- Lists recordings via:
    1) /v2/report/cloud_recording (preferred)
    2) fallback: /v2/users/me/recordings
- Selects M4A using file_type OR file_extension.
- Builds RAW filename as GMTYYYYMMDD-HHMMSS_Recording.m4a when Zoom doesn't provide file_name.
- Repairs legacy uploads named GMT00000000-000000_*.m4a by re-uploading once with correct name.
- Idempotency via STATE_PATH JSON keyed by recording_file.id.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

ZOOM_TOKEN_URL = "https://zoom.us/oauth/token"
ZOOM_REPORT_RECORDINGS_URL = "https://api.zoom.us/v2/report/cloud_recording"
ZOOM_USER_RECORDINGS_URL = "https://api.zoom.us/v2/users/me/recordings"

IA_S3_BASE = "https://s3.us.archive.org"
DEFAULT_PAGE_SIZE = 300

LEGACY_ZERO_PREFIX = "GMT00000000-000000_"


class SyncError(RuntimeError):
    """Sync failure."""


@dataclass(frozen=True)
class Env:
    ia_access_key: str
    ia_secret_key: str
    zoom_account_id: str
    zoom_client_id: str
    zoom_client_secret: str
    raw_ia_identifier: str
    lookback_minutes: int
    state_path: str
    debug: bool
    repair_legacy_zero_names: bool


def _require_env(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise SyncError(f"Missing required env var: {name}")
    return v


def load_env() -> Env:
    return Env(
        ia_access_key=_require_env("IA_ACCESS_KEY"),
        ia_secret_key=_require_env("IA_SECRET_KEY"),
        zoom_account_id=_require_env("ZOOM_ACCOUNT_ID"),
        zoom_client_id=_require_env("ZOOM_CLIENT_ID"),
        zoom_client_secret=_require_env("ZOOM_CLIENT_SECRET"),
        raw_ia_identifier=os.getenv("RAW_IA_IDENTIFIER", "FSPraw"),
        lookback_minutes=int(os.getenv("LOOKBACK_MINUTES", "90")),
        state_path=os.getenv("STATE_PATH", ".zoom_raw_state.json"),
        debug=os.getenv("DEBUG", "0") == "1",
        repair_legacy_zero_names=os.getenv("REPAIR_LEGACY_ZERO_NAMES", "1") == "1",
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_date(dt: datetime) -> str:
    return dt.date().isoformat()


def safe_write_json(path: str, data: Dict[str, Any]) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def load_state(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {"uploaded": {}}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or "uploaded" not in data or not isinstance(data["uploaded"], dict):
        raise SyncError(f"State file malformed: {path}")
    return data


_ISO_FRACTION_RE = re.compile(r"(\.\d+)(Z|[+-]\d{2}:\d{2})$")


def parse_zoom_dt(value: Any) -> Optional[datetime]:
    """
    Zoom timestamps may be:
    - 2026-02-23T10:12:13Z
    - 2026-02-23T10:12:13.123Z
    - 2026-02-23T10:12:13+00:00
    """
    if not isinstance(value, str) or not value.strip():
        return None
    s = value.strip()
    s = _ISO_FRACTION_RE.sub(r"\2", s)  # strip .ms
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s).astimezone(timezone.utc)
    except Exception:
        return None


def zoom_s2s_token(env: Env, session: requests.Session) -> str:
    creds = f"{env.zoom_client_id}:{env.zoom_client_secret}".encode("utf-8")
    auth = base64.b64encode(creds).decode("ascii")
    url = f"{ZOOM_TOKEN_URL}?grant_type=account_credentials&account_id={env.zoom_account_id}"
    r = session.post(url, headers={"Authorization": f"Basic {auth}"}, timeout=30)
    if r.status_code != 200:
        raise SyncError(f"Zoom token failed: HTTP {r.status_code} - {r.text[:400]}")
    data = r.json()
    token = data.get("access_token")
    if not token:
        raise SyncError("Zoom token response missing access_token.")
    if env.debug and data.get("scope"):
        print(f"[debug] zoom_token_scopes={data.get('scope')}")
    return token


def _zoom_get_json(
    session: requests.Session, url: str, token: str, params: Dict[str, Any]
) -> Tuple[int, Dict[str, Any], str]:
    r = session.get(url, headers={"Authorization": f"Bearer {token}"}, params=params, timeout=60)
    text = r.text
    try:
        js = r.json() if r.content else {}
    except Exception:
        js = {}
    return r.status_code, js, text


def _fetch_all(session: requests.Session, token: str, base_url: str, from_date: str, to_date: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    next_page_token: Optional[str] = None
    while True:
        params: Dict[str, Any] = {"from": from_date, "to": to_date, "page_size": DEFAULT_PAGE_SIZE}
        if next_page_token:
            params["next_page_token"] = next_page_token

        status, js, text = _zoom_get_json(session, base_url, token, params)
        if status != 200:
            raise SyncError(f"Zoom list failed ({base_url}): HTTP {status} - {text[:400]}")

        meetings = js.get("meetings") or js.get("recordings") or []
        if not isinstance(meetings, list):
            raise SyncError(f"Zoom list unexpected shape from {base_url}.")

        out.extend([m for m in meetings if isinstance(m, dict)])
        next_page_token = js.get("next_page_token") or None
        if not next_page_token:
            break
        time.sleep(0.2)
    return out


def list_recordings(session: requests.Session, token: str, from_date: str, to_date: str) -> Iterable[Dict[str, Any]]:
    try:
        yield from _fetch_all(session, token, ZOOM_REPORT_RECORDINGS_URL, from_date, to_date)
        return
    except SyncError:
        yield from _fetch_all(session, token, ZOOM_USER_RECORDINGS_URL, from_date, to_date)


def is_m4a(rf: Dict[str, Any]) -> bool:
    ft = str(rf.get("file_type") or "").upper()
    fe = str(rf.get("file_extension") or "").upper()
    return ft == "M4A" or fe == "M4A"


def recording_start_utc(rf: Dict[str, Any], meeting: Dict[str, Any]) -> Optional[datetime]:
    return (
        parse_zoom_dt(rf.get("recording_start"))
        or parse_zoom_dt(rf.get("start_time"))
        or parse_zoom_dt(meeting.get("start_time"))
    )


def build_remote_name(
    rf: Dict[str, Any],
    meeting: Dict[str, Any],
    used_names: set[str],
) -> str:
    name = rf.get("file_name")
    if isinstance(name, str) and name.strip().lower().endswith(".m4a"):
        candidate = name.strip()
    else:
        dt = recording_start_utc(rf, meeting)
        rid = str(rf.get("id") or "unknown")
        if dt:
            candidate = f"GMT{dt:%Y%m%d-%H%M%S}_Recording.m4a"
        else:
            candidate = f"{LEGACY_ZERO_PREFIX}{rid}.m4a"

    if candidate in used_names:
        rid = str(rf.get("id") or "x")
        candidate = candidate[:-4] + f"_{rid[:8]}.m4a"

    used_names.add(candidate)
    return candidate


def zoom_download(session: requests.Session, token: str, download_url: str) -> bytes:
    r = session.get(download_url, headers={"Authorization": f"Bearer {token}"}, timeout=180)
    if r.status_code != 200:
        raise SyncError(f"Zoom download failed: HTTP {r.status_code} - {r.text[:400]}")
    return r.content


def ia_put(session: requests.Session, env: Env, identifier: str, filename: str, content: bytes) -> None:
    url = f"{IA_S3_BASE}/{identifier}/{filename}"
    headers = {
        "Authorization": f"LOW {env.ia_access_key}:{env.ia_secret_key}",
        "Content-Type": "audio/mp4",
    }
    r = session.put(url, data=content, headers=headers, timeout=240)
    if r.status_code not in (200, 201):
        raise SyncError(f"IA upload failed for {identifier}/{filename}: HTTP {r.status_code} - {r.text[:400]}")


def main() -> int:
    env = load_env()
    session = requests.Session()
    state = load_state(env.state_path)
    uploaded: Dict[str, Any] = state["uploaded"]

    token = zoom_s2s_token(env, session)

    now = utc_now()
    window_start = now - timedelta(minutes=env.lookback_minutes)

    from_date = iso_date(window_start)
    to_date = iso_date(now)

    meetings = list(list_recordings(session, token, from_date, to_date))
    print(f"[info] meetings_in_range={len(meetings)} from={from_date} to={to_date} window_start_utc={window_start.isoformat()}")

    used_names: set[str] = set()
    for v in uploaded.values():
        if isinstance(v, dict) and isinstance(v.get("remote_name"), str):
            used_names.add(v["remote_name"])
        if isinstance(v, dict) and isinstance(v.get("legacy_remote_names"), list):
            for n in v["legacy_remote_names"]:
                if isinstance(n, str):
                    used_names.add(n)

    uploaded_count = 0
    skipped_count = 0
    repaired_count = 0
    seen_m4a = 0

    for m in meetings:
        files = m.get("recording_files") or []
        if not isinstance(files, list):
            continue

        for rf in files:
            if not isinstance(rf, dict):
                continue
            if not rf.get("download_url"):
                continue
            if not is_m4a(rf):
                continue

            seen_m4a += 1
            rid = str(rf.get("id") or "").strip()
            if not rid:
                continue

            dt = recording_start_utc(rf, m)
            if dt and dt < window_start:
                if env.debug:
                    print(f"[debug] skip old rid={rid} dt={dt.isoformat()}")
                continue

            entry = uploaded.get(rid)
            if entry:
                old_name = str(entry.get("remote_name") or "")
                needs_repair = (
                    env.repair_legacy_zero_names
                    and old_name.startswith(LEGACY_ZERO_PREFIX)
                    and not entry.get("fixed_name_uploaded")
                )
                if not needs_repair:
                    skipped_count += 1
                    continue

                new_name = build_remote_name(rf, m, used_names)
                if new_name.startswith(LEGACY_ZERO_PREFIX):
                    skipped_count += 1
                    continue

                print(f"[info] Repair upload: {old_name} -> {new_name}")
                content = zoom_download(session, token, rf["download_url"])
                ia_put(session, env, env.raw_ia_identifier, new_name, content)

                legacy = entry.get("legacy_remote_names")
                if not isinstance(legacy, list):
                    legacy = []
                if old_name and old_name not in legacy:
                    legacy.append(old_name)

                entry["legacy_remote_names"] = legacy
                entry["remote_name"] = new_name
                entry["fixed_name_uploaded"] = True
                entry["recording_start_utc"] = dt.isoformat() if dt else None
                repaired_count += 1
                uploaded_count += 1
                continue

            remote_name = build_remote_name(rf, m, used_names)
            if env.debug:
                print(f"[debug] upload rid={rid} remote_name={remote_name} dt={dt.isoformat() if dt else None}")

            content = zoom_download(session, token, rf["download_url"])
            print(f"[info] Uploading to IA RAW {env.raw_ia_identifier}/{remote_name} bytes={len(content)}")
            ia_put(session, env, env.raw_ia_identifier, remote_name, content)

            uploaded[rid] = {
                "remote_name": remote_name,
                "uploaded_at_utc": now.isoformat(),
                "meeting_id": m.get("id"),
                "meeting_uuid": m.get("uuid"),
                "recording_start_utc": dt.isoformat() if dt else None,
            }
            uploaded_count += 1

    state["uploaded"] = uploaded
    safe_write_json(env.state_path, state)

    print(f"[ok] SeenM4A={seen_m4a} Uploaded={uploaded_count} Repaired={repaired_count} Skipped={skipped_count} State={env.state_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SyncError as e:
        print(f"[error] {e}", file=sys.stderr)
        raise SystemExit(2)
    except Exception as e:
        print(f"[error] Unexpected: {e}", file=sys.stderr)
        raise SystemExit(3)
