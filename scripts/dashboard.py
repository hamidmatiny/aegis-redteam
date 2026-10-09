#!/usr/bin/env python3
"""Red-team dashboard computed from the corpus. No model involved.

Headline: unique open vectors right now = distinct prompts whose LATEST live
gateway retest returned HTTP 200. A vector is one exact prompt text, so repeated
retests of the same prompt count once. Retest rows and all-time totals are
reported separately and labelled as history.

Status comes from memory/attack-corpus.jsonl only, never from findings.md.

  python3 scripts/dashboard.py            # Slack/markdown text
  python3 scripts/dashboard.py --json     # machine-readable
  python3 scripts/dashboard.py --write    # also rewrite dashboard.yaml
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "memory" / "attack-corpus.jsonl"
DASHBOARD = ROOT / "dashboard.yaml"
REAL = "real-free-tier"


def load(path: Path = CORPUS) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line, strict=False))
        except ValueError:
            continue
    return rows


def vector_key(prompt: str) -> str:
    return hashlib.sha1(prompt.encode("utf-8")).hexdigest()[:8]


def is_benign(row: dict) -> bool:
    tag = f"{row.get('category') or ''} {row.get('id') or ''}".lower()
    return "benign" in tag or "control" in tag


def live_status(row: dict) -> int | None:
    """HTTP status of a live gateway retest. Real-backend scoring rows are not live retests."""
    if row.get("backend") == REAL:
        return None
    status = row.get("http_status")
    if status in (200, 403):
        return int(status)
    result = str(row.get("result") or "").upper()
    if result == "BYPASS":
        return 200
    if result in ("BLOCKED", "BLOCK"):
        return 403
    return None


def _days_ago(days: int) -> str:
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def summarize(rows: list[dict]) -> dict:
    first_seen: dict[str, dict] = {}
    latest_live: dict[str, dict] = {}
    latest_real: dict[str, dict] = {}
    live_rows = 0
    live_200 = 0
    for row in sorted(rows, key=lambda r: r.get("ts") or ""):
        key = vector_key(row.get("prompt") or "")
        first_seen.setdefault(key, row)
        status = live_status(row)
        if status is not None:
            live_rows += 1
            live_200 += status == 200
            latest_live[key] = {**row, "_status": status}
        elif row.get("backend") == REAL:
            latest_real[key] = row

    def entry(key: str) -> dict:
        last = latest_live[key]
        first = first_seen[key]
        return {
            "vector": key,
            "first_id": first.get("id"),
            "first_seen": first.get("ts"),
            "latest_id": last.get("id"),
            "latest_ts": last.get("ts"),
            "latest_status": last["_status"],
            "stale": (last.get("ts") or "") < _days_ago(7),
            "layer": last.get("layer"),
        }

    attack = [k for k in latest_live if not is_benign(latest_live[k])]
    benign = [k for k in latest_live if is_benign(latest_live[k])]
    # A 200 the team judged correct (result ALLOWED, e.g. a plain capability question) is not open.
    open_vectors = sorted(
        (entry(k) for k in attack
         if latest_live[k]["_status"] == 200 and str(latest_live[k].get("result")).upper() != "ALLOWED"),
        key=lambda e: e["first_seen"] or "",
    )
    false_positives = sorted((entry(k) for k in benign if latest_live[k]["_status"] == 403), key=lambda e: e["first_seen"] or "")
    real_allowed = sorted(
        k for k, r in latest_real.items() if str(r.get("result")).upper() == "ALLOWED" and not is_benign(first_seen[k])
    )
    return {
        "unique_open_vectors": len(open_vectors),
        "open_vectors": open_vectors,
        "unique_attack_vectors_retested": len(attack),
        "benign_false_positives_now": false_positives,
        "retest_rows": live_rows - len(latest_live),
        "real_backend_allowed_latest": real_allowed,
        "history": {
            "live_rows_all_time": live_rows,
            "live_rows_200_all_time": live_200,
            "corpus_rows": len(rows),
        },
        "as_of": max((r.get("ts") or "" for r in rows), default=""),
    }


def render(s: dict) -> str:
    lines = [
        f"*Unique open vectors right now: {s['unique_open_vectors']}* "
        f"(of {s['unique_attack_vectors_retested']} distinct attack prompts; status = latest live retest, 200 = open)",
    ]
    for v in s["open_vectors"]:
        stale = " (STALE: no retest in 7 days)" if v["stale"] else ""
        lines.append(f"• {v['first_id']} — first seen {v['first_seen']}, latest retest {v['latest_ts']}: 200{stale}")
    if s["benign_false_positives_now"]:
        lines.append(f"*Benign controls blocked right now (false positives): {len(s['benign_false_positives_now'])}*")
        for v in s["benign_false_positives_now"]:
            lines.append(f"• {v['first_id']} — latest {v['latest_ts']}: 403 at {v['layer']}")
    if s["real_backend_allowed_latest"]:
        lines.append(
            f"Real-backend scoring, latest ALLOWED (read the completion before calling it a bypass): "
            f"{len(s['real_backend_allowed_latest'])}"
        )
    lines.append(f"Retest rows (repeat tests of already-known prompts): {s['retest_rows']}")
    h = s["history"]
    lines.append(
        f"History, all-time rows including retests (not current exposure): {h['live_rows_all_time']} live rows, "
        f"{h['live_rows_200_all_time']} returned 200; {h['corpus_rows']} corpus rows total. As of {s['as_of']}."
    )
    return "\n".join(lines)


def write_dashboard(s: dict) -> None:
    h = s["history"]
    DASHBOARD.write_text(
        "title: AEGIS Redteam\n"
        "metrics:\n"
        "  - id: unique_open_vectors\n"
        "    label: Unique open vectors (latest live retest = 200)\n"
        f"    value: \"{s['unique_open_vectors']}\"\n"
        "  - id: benign_false_positives\n"
        "    label: Benign controls blocked now\n"
        f"    value: \"{len(s['benign_false_positives_now'])}\"\n"
        "  - id: retest_rows\n"
        "    label: Retest rows\n"
        f"    value: \"{s['retest_rows']}\"\n"
        "  - id: history_live_rows\n"
        "    label: History — all-time live rows / returned 200\n"
        f"    value: \"{h['live_rows_all_time']} / {h['live_rows_200_all_time']}\"\n"
        f"as_of: \"{s['as_of']}\"\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    args = parser.parse_args()
    summary = summarize(load(args.corpus))
    if args.write:
        write_dashboard(summary)
    print(json.dumps(summary, indent=2) if args.json else render(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
