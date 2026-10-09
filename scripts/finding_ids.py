#!/usr/bin/env python3
"""Stable finding IDs. One ID = one exact prompt, forever.

memory/finding-ids.json maps each BYPASS-NNN to the sha256 of the exact prompt
it was recorded with. The hash is public-safe; the prompt itself stays in the
gitignored corpus.

Rules this script enforces:
  - An ID is never reused for a different prompt (BYPASS-006 was Log4j, then a
    batch run reused it for a TOML prompt on 2026-10-09).
  - A new prompt always gets a new ID. A reworded variant of a known finding
    gets its own ID with `variant_of` pointing at the original.
  - IDs are allocated here, never picked by hand.

  python3 scripts/finding_ids.py assign --corpus-id ID --title T --family F [--variant-of BYPASS-NNN]
  python3 scripts/finding_ids.py lookup --corpus-id ID
  python3 scripts/finding_ids.py check      # findings.md and corpus agree with the registry
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "memory" / "finding-ids.json"
CORPUS = ROOT / "memory" / "attack-corpus.jsonl"
FINDINGS = ROOT / "memory" / "findings.md"
ID_RE = re.compile(r"^BYPASS-(\d{3,})$")
HEADER_RE = re.compile(r"^## (BYPASS-\d{3,})\b", re.M)


def prompt_hash(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def load_registry(path: Path = REGISTRY) -> dict:
    if not path.exists():
        return {"findings": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def save_registry(reg: dict, path: Path = REGISTRY) -> None:
    path.write_text(json.dumps(reg, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def load_corpus(path: Path = CORPUS) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line, strict=False))
        except ValueError:
            continue
    return rows


def prompt_for(corpus_id: str, rows: list[dict]) -> str:
    for row in rows:
        if row.get("id") == corpus_id and row.get("prompt"):
            return row["prompt"]
    raise SystemExit(f"no corpus row with id {corpus_id!r} and a prompt")


def by_hash(reg: dict, digest: str) -> str | None:
    for fid, entry in reg["findings"].items():
        if entry["prompt_sha256"] == digest:
            return fid
    return None


def next_id(reg: dict) -> str:
    nums = [int(ID_RE.match(fid).group(1)) for fid in reg["findings"] if ID_RE.match(fid)]
    nums += [int(n) for n in reg.get("retired", [])]
    return f"BYPASS-{max(nums, default=0) + 1:03d}"


def assign(reg: dict, prompt: str, *, corpus_id: str, title: str, family: str,
           variant_of: str | None = None, now: str | None = None) -> tuple[str, bool]:
    """Return (id, created). A known prompt keeps its ID; a new prompt never takes an old one."""
    digest = prompt_hash(prompt)
    existing = by_hash(reg, digest)
    if existing:
        return existing, False
    if variant_of and variant_of not in reg["findings"]:
        raise SystemExit(f"--variant-of {variant_of} is not a registered finding")
    fid = next_id(reg)
    reg["findings"][fid] = {
        "prompt_sha256": digest,
        "corpus_id": corpus_id,
        "title": title,
        "family": family,
        "variant_of": variant_of,
        "assigned_at": now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return fid, True


def check(reg: dict, rows: list[dict], findings_text: str) -> list[str]:
    """Problems that mean an ID is being reused or invented."""
    problems = []
    seen_hash: dict[str, str] = {}
    for fid, entry in reg["findings"].items():
        if not ID_RE.match(fid):
            problems.append(f"{fid}: not a BYPASS-NNN id")
        other = seen_hash.setdefault(entry["prompt_sha256"], fid)
        if other != fid:
            problems.append(f"{fid} and {other} share one prompt hash")
        if entry.get("variant_of") and entry["variant_of"] not in reg["findings"]:
            problems.append(f"{fid}: variant_of {entry['variant_of']} is not registered")
    headers = HEADER_RE.findall(findings_text)
    for fid in headers:
        if fid not in reg["findings"]:
            problems.append(f"findings.md has {fid}, which the registry never assigned")
    for fid in {h for h in headers if headers.count(h) > 1}:
        problems.append(f"findings.md has more than one section for {fid}")
    for row in rows:
        fid = row.get("finding_id")
        if not fid or not row.get("prompt"):
            continue
        entry = reg["findings"].get(fid)
        if entry is None:
            problems.append(f"corpus row {row.get('id')} cites {fid}, which is not registered")
        elif entry["prompt_sha256"] != prompt_hash(row["prompt"]):
            problems.append(
                f"corpus row {row.get('id')} cites {fid} for a different prompt "
                f"(registered: {entry['corpus_id']}); a new prompt needs `assign`"
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("assign")
    a.add_argument("--corpus-id", required=True)
    a.add_argument("--title", required=True)
    a.add_argument("--family", required=True)
    a.add_argument("--variant-of")
    lk = sub.add_parser("lookup")
    lk.add_argument("--corpus-id", required=True)
    sub.add_parser("check")
    args = p.parse_args(argv)

    reg = load_registry()
    rows = load_corpus()
    if args.cmd == "assign":
        fid, created = assign(reg, prompt_for(args.corpus_id, rows), corpus_id=args.corpus_id,
                              title=args.title, family=args.family, variant_of=args.variant_of)
        if created:
            save_registry(reg)
        print(json.dumps({"id": fid, "created": created, **reg["findings"][fid]}))
        return 0
    if args.cmd == "lookup":
        fid = by_hash(reg, prompt_hash(prompt_for(args.corpus_id, rows)))
        print(json.dumps({"id": fid}))
        return 0 if fid else 1
    problems = check(reg, rows, FINDINGS.read_text(encoding="utf-8") if FINDINGS.exists() else "")
    for line in problems:
        print(line)
    print(f"{len(reg['findings'])} registered ids, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
