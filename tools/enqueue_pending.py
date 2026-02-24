#!/usr/bin/env python3
"""
Append a publish request line into queue/pending.json (dedup).

Usage:
  python tools/enqueue_pending.py --line "..."
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

QUEUE_PATH = "queue/pending.json"


def load_queue() -> Dict[str, Any]:
    if not os.path.exists(QUEUE_PATH):
        return {"pending": []}
    with open(QUEUE_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or "pending" not in data or not isinstance(data["pending"], list):
        return {"pending": []}
    return data


def save_queue(data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(QUEUE_PATH), exist_ok=True)
    tmp = QUEUE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, QUEUE_PATH)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--line", required=True)
    args = ap.parse_args()

    line = args.line.strip()
    if not line:
        raise SystemExit("line is empty")

    data = load_queue()
    pending: List[Dict[str, Any]] = data["pending"]

    # dedupe by exact line
    if any(isinstance(x, dict) and x.get("line") == line for x in pending):
        print("[ok] already queued")
        return 0

    pending.append(
        {
            "line": line,
            "queued_at_utc": datetime.now(timezone.utc).isoformat(),
        }
    )
    data["pending"] = pending
    save_queue(data)
    print("[ok] queued")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
