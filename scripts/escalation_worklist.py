#!/usr/bin/env python3
"""Build the full bypass-escalation worklist in one deterministic pass.

The escalate step of /attack-gateway used to loop in the model: find the open
bypasses, call `finding_ids.py lookup` once per row, then hand-assemble each
escalation package. On a batch with several open vectors that loop is slow and
token-heavy, and on 2026-10-09 a scheduled run was killed by the watchdog mid
escalate. This script does the whole deterministic part at once:

  * current open vectors come from the same logic the dashboard uses
    (distinct prompts whose LATEST live retest returned 200, minus ALLOWED),
  * each is resolved against the finding-id registry (known id, or NEW = a
    prompt that still needs `finding_ids.py assign`),
  * the exact prompt and a response excerpt are pulled from the corpus.

The model then sends what this prints; it no longer rediscovers it per row.

  python3 scripts/escalation_worklist.py            # human-readable
  python3 scripts/escalation_worklist.py --json      # machine-readable
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dashboard import CORPUS, load, summarize  # noqa: E402
from finding_ids import REGISTRY, by_hash, load_registry, prompt_hash  # noqa: E402

EXCERPT_KEYS = ("response_excerpt", "response", "excerpt", "completion", "output")


def _excerpt(row: dict, limit: int = 300) -> str:
    for key in EXCERPT_KEYS:
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:limit]
    return ""


def build_worklist(corpus_rows: list[dict], registry: dict) -> dict:
    summary = summarize(corpus_rows)
    by_id: dict = {}
    for row in corpus_rows:
        by_id.setdefault(row.get("id"), row)
    items = []
    for vector in summary["open_vectors"]:
        row = by_id.get(vector["latest_id"]) or {}
        prompt = row.get("prompt") or ""
        fid = by_hash(registry, prompt_hash(prompt)) if prompt else None
        entry = registry["findings"].get(fid) if fid else None
        items.append({
            "finding_id": fid,
            "status": "known" if fid else "NEW",
            "vector": vector["vector"],
            "first_id": vector["first_id"],
            "latest_id": vector["latest_id"],
            "latest_ts": vector["latest_ts"],
            "layer": vector["layer"],
            "family": entry.get("family") if entry else None,
            "title": entry.get("title") if entry else None,
            "prompt": prompt,
            "response_excerpt": _excerpt(row),
        })
    return {
        "open_count": len(items),
        "needs_new_id": [i["latest_id"] for i in items if i["finding_id"] is None],
        "items": items,
        "as_of": summary["as_of"],
    }


def render(worklist: dict) -> str:
    if not worklist["open_count"]:
        return f"No open vectors to escalate. As of {worklist['as_of']}."
    lines = [f"{worklist['open_count']} open vector(s) to escalate (as of {worklist['as_of']}):"]
    for item in worklist["items"]:
        label = item["finding_id"] or "NEW (run finding_ids.py assign first)"
        title = f" — {item['title']}" if item["title"] else ""
        lines.append(f"• {label}{title}")
        lines.append(f"    corpus row {item['latest_id']} (first {item['first_id']}), latest retest {item['latest_ts']}, layer {item['layer']}")
    if worklist["needs_new_id"]:
        lines.append(f"Needs a new id assigned first: {', '.join(worklist['needs_new_id'])}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--registry", type=Path, default=REGISTRY)
    args = parser.parse_args(argv)

    corpus_rows = load(args.corpus)
    registry = load_registry(args.registry)
    worklist = build_worklist(corpus_rows, registry)
    print(json.dumps(worklist, indent=2, ensure_ascii=False) if args.json else render(worklist))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
