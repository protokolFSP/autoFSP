# tools/zoom_to_ia_raw_sync.py
#!/usr/bin/env python3
"""
Zoom cloud recording M4A -> Internet Archive RAW (FSPraw)

Fixes:
- Uses /v2/meetings/{uuid}/recordings to get reliable file_name + recording_start.
- Generates RAW filename as GMTYYYYMMDD-HHMMSS_Recording.m4a if file_name missing.
- If user deleted files on IA, re-uploads even if state says uploaded (checks IA metadata).
- Idempotency keyed by recording_file.id in STATE_PATH (.zoom_raw_state.json).
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import quote

import requests

ZOOM_TOKEN_URL = "https://zoom.us/oauth/token"
ZOOM_REPORT_RECORDINGS_URL = "https://api.zoom.us/v2/report/cloud_recording"
ZOOM_USER_RECORDINGS_URL = "https://api.zoom.us/v2/users/me/recordings"
ZOOM_MEETING_RECORDINGS_URL = "https://api.zoom.us/v2/meetings/{meeting_uuid}/recordings"

IA_S3_BASE = "https://s3.us.archive.org"
IA_META_URL = "https://archive.org/metadata/{identifier}"
DEFAULT_PAGE_SIZE = 300


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


def parse_zoom_dt(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # strip fractional seconds if present
    if "." in s:
        left, right = s.split(".", 1)
        if "+" in right:
            _, tz = right.split("+", 1)
            s = f"{left}+{tz}"
        elif "-" in right and right.count("-") >= 1 and ":" in right:
            # rare
            parts = right.split("-", 1)
            s = f"{left}-{parts[1]}"
        else:
            s = left
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


def ia_existing_files(identifier: str, session: requests.Session) -> Set[str]:
    r = session.get(IA_META_URL.format(identifier=identifier), timeout=60)
    if r.status_code != 200:
        raise SyncError(f"IA metadata fetch failed for {identifier}: HTTP {r.status_code} - {r.text[:200]}")
    js = r.json()
    files = js.get("files") or []
    if not isinstance(files, list):
        return set()
    out: Set[str] = set()
    for f in files:
        if isinstance(f, dict) and isinstance(f.get("name"), str):
            out.add(f["name"])
    return out


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


def list_meetings(session: requests.Session, token: str, from_date: str, to_date: str) -> List[Dict[str, Any]]:
    # Prefer report endpoint, fallback to users/me/recordings.
    try:
        return _fetch_all(session, token, ZOOM_REPORT_RECORDINGS_URL, from_date, to_date)
    except SyncError:
        return _fetch_all(session, token, ZOOM_USER_RECORDINGS_URL, from_date, to_date)


def encode_meeting_uuid(uuid: str) -> str:
    # Zoom requires double-encoding when UUID contains '/'
    return quote(quote(uuid, safe=""), safe="")


def get_meeting_recordings(session: requests.Session, token: str, meeting_uuid: str) -> Dict[str, Any]:
    url = ZOOM_MEETING_RECORDINGS_URL.format(meeting_uuid=encode_meeting_uuid(meeting_uuid))
    r = session.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=60)
    if r.status_code != 200:
        raise SyncError(f"Zoom meeting recordings failed ({url}): HTTP {r.status_code} - {r.text[:400]}")
    return r.json()


def is_m4a_file(rf: Dict[str, Any]) -> bool:
    ft = str(rf.get("file_type") or "").upper()
    fe = str(rf.get("file_extension") or "").upper()
    return ft == "M4A" or fe == "M4A"


def build_remote_filename(rf: Dict[str, Any]) -> str:
    name = rf.get("file_name")
    if isinstance(name, str) and name.strip().lower().endswith(".m4a"):
        return name.strip()

    dt = parse_zoom_dt(rf.get("recording_start") or rf.get("start_time"))
    if dt:
        return f"GMT{dt:%Y%m%d-%H%M%S}_Recording.m4a"

    rid = str(rf.get("id") or "unknown")
    return f"GMT00000000-000000_{rid}.m4a"


def zoom_download(session: requests.Session, token: str, download_url: str) -> bytes:
    r = session.get(download_url, headers={"Authorization": f"Bearer {token}"}, timeout=240)
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

    ia_files = ia_existing_files(env.raw_ia_identifier, session)

    meetings = list_meetings(session, token, from_date, to_date)
    print(f"[info] meetings={len(meetings)} range={from_date}..{to_date} window_start_utc={window_start.isoformat()}")

    seen_m4a = 0
    uploaded_count = 0
    skipped_count = 0
    reuploaded_missing_count = 0

    for m in meetings:
        meeting_uuid = m.get("uuid")
        if not isinstance(meeting_uuid, str) or not meeting_uuid.strip():
            continue

        meeting_start = parse_zoom_dt(m.get("start_time"))
        if meeting_start and meeting_start < window_start:
            continue

        details = get_meeting_recordings(session, token, meeting_uuid)
        files = details.get("recording_files") or []
        if not isinstance(files, list):
            continue

        for rf in files:
            if not isinstance(rf, dict):
                continue
            if not rf.get("download_url"):
                continue
            if not is_m4a_file(rf):
                continue

            seen_m4a += 1
            rid = str(rf.get("id") or "").strip()
            if not rid:
                continue

            remote_name = build_remote_filename(rf)

            already = uploaded.get(rid)
            if already:
                prev_name = str(already.get("remote_name") or "")
                # if IA file deleted, re-upload
                if prev_name and prev_name not in ia_files:
                    if env.debug:
                        print(f"[debug] reupload missing IA file rid={rid} name={prev_name}")
                    content = zoom_download(session, token, rf["download_url"])
                    ia_put(session, env, env.raw_ia_identifier, prev_name, content)
                    ia_files.add(prev_name)
                    reuploaded_missing_count += 1
                    uploaded_count += 1
                else:
                    skipped_count += 1
                continue

            # If state reset but file already exists on IA, just record it
            if remote_name in ia_files:
                uploaded[rid] = {"remote_name": remote_name, "uploaded_at_utc": now.isoformat(), "note": "found_on_ia"}
                skipped_count += 1
                continue

            if env.debug:
                print(f"[debug] upload rid={rid} remote_name={remote_name} meeting_uuid={meeting_uuid}")

            content = zoom_download(session, token, rf["download_url"])
            print(f"[info] Uploading {env.raw_ia_identifier}/{remote_name} bytes={len(content)}")
            ia_put(session, env, env.raw_ia_identifier, remote_name, content)
            ia_files.add(remote_name)

            uploaded[rid] = {
                "remote_name": remote_name,
                "uploaded_at_utc": now.isoformat(),
                "meeting_uuid": meeting_uuid,
                "recording_start_utc": (parse_zoom_dt(rf.get("recording_start")) or "").isoformat() if parse_zoom_dt(rf.get("recording_start")) else None,
            }
            uploaded_count += 1

    state["uploaded"] = uploaded
    safe_write_json(env.state_path, state)

    print(
        f"[ok] SeenM4A={seen_m4a} Uploaded={uploaded_count} "
        f"ReuploadedMissing={reuploaded_missing_count} Skipped={skipped_count} State={env.state_path}"
    )
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
