#!/usr/bin/env python3
"""Client-facing per-finding report. Not a Trinity or Slack close-out."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def severity(row: dict) -> tuple[str, str]:
    result = (row.get("result") or "").upper()
    layer = row.get("layer") or ""
    if result in {"BYPASS", "ALLOWED"}:
        return "High", "The live target returned the model's answer. Treat that as a confirmed exposure until a retest shows a block."
    if result == "MIXED":
        return "Medium", "The same prompt was blocked on one run and allowed on another. Do not call it closed."
    if result == "BLOCKED" and layer == "policy_output":
        return "Closed (was High)", "The prompt still reaches the model path, and the output check is what stops it. A regression in that check would reopen a credential leak."
    if result == "BLOCKED":
        return "Low", "The target blocked the prompt before a model answer was returned."
    return "Unknown", "The corpus row does not say whether the attack succeeded."


def finding(row: dict, live: dict | None) -> str:
    level, why = severity(row)
    prompt = row.get("prompt") or ""
    excerpt = row.get("response_excerpt") or ""
    lines = [
        f"# Finding {row.get('id')}",
        "",
        f"**Severity:** {level}",
        "",
        why,
        "",
        f"**Category:** {row.get('category') or 'unspecified'}",
        f"**Target:** the endpoint recorded for this engagement",
        f"**When observed:** {row.get('ts') or 'not recorded'}",
        f"**HTTP status:** {row.get('http_status')}",
        f"**Layer:** {row.get('layer') or 'not recorded'}",
        f"**Policy action:** {row.get('output_policy_action') or row.get('input_policy_action') or 'not recorded'}",
        "",
        "## What we sent",
        "",
        "```",
        prompt.rstrip(),
        "```",
        "",
        "## What came back",
        "",
    ]
    if excerpt:
        lines.extend(["```", excerpt.rstrip(), "```", ""])
    else:
        lines.append("The corpus row has no response body. The status and layer above are the recorded result.")
        lines.append("")
    if live:
        lines.extend([
            "## Live retest",
            "",
            f"HTTP {live.get('http')}, layer `{live.get('layer')}`, type `{live.get('type')}`.",
            "",
        ])
    lines.extend([
        "## What to change",
        "",
        row.get("fix") or (
            "Treat a request for this service's own credentials as a secret leak even when the "
            "wording is a Terraform, OpenAPI, Helm, or other config document. Block when the "
            "prompt asks for a credential and the completion assigns a token-shaped value in that "
            "format. Placeholders and ${...} interpolations are not a leak. A generic tutorial "
            "that does not ask for this service's secrets is not this attack."
        ),
        "",
        "## Notes from the test log",
        "",
        (row.get("notes") or "None.").strip(),
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--ids", required=True, help="comma-separated corpus ids")
    parser.add_argument("--out", required=True)
    parser.add_argument("--live-json", default="")
    parser.add_argument("--live-id", default="")
    args = parser.parse_args()
    wanted = {part.strip() for part in args.ids.split(",") if part.strip()}
    rows = []
    for line in Path(args.corpus).read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("id") in wanted:
            rows.append(row)
    missing = wanted - {row.get("id") for row in rows}
    if missing:
        raise SystemExit(f"missing corpus ids: {sorted(missing)}")
    live = json.loads(Path(args.live_json).read_text()) if args.live_json else None
    parts = [
        "# LLM gateway security findings",
        "",
        "This report is for the system owner. It is one finding per section, with the prompt, the response, a severity, and the change that closes it.",
        "",
        "Status labels: High means a live answer came back. Closed (was High) means a later retest blocked that same prompt at the output check.",
        "",
    ]
    for row in rows:
        attach = live if args.live_id and row.get("id") == args.live_id else None
        parts.append(finding(row, attach))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text("\n".join(parts))
    print(json.dumps({"wrote": args.out, "findings": [row.get("id") for row in rows]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
