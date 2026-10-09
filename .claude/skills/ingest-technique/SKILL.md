---
name: ingest-technique
description: Accept a Protocol D attack-technique handoff; normalize; test against the live gateway.
---

# /ingest-technique

## Steps

1. Parse the inbound message for: technique name/source URL, example prompt(s), who found it, category guess.
2. Normalize into 1–3 concrete prompts suitable for `POST /v1/chat/completions`.
3. Run them via `scripts/harness.py` (same allowlist as `/attack-gateway`). A host that is not on `memory/authorized-targets.json` with a real `authorization_ref` is refused before any request.
4. Append results to `memory/attack-corpus.jsonl` with `source: protocol_d` and the finder agent name.
5. If BYPASS → escalate to `aegis-ceo` (decision point). If BLOCKED → reply to finder/manager with "caught" + layer. Never claim a test you did not run.
6. Slack close-out.
