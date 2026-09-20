---
name: file-bypass
description: Package a confirmed live bypass for aegis-ceo decision and Track A fix notes.
---

# /file-bypass

## Steps

1. Require a real transcript (prompt + HTTP status + response body / aegis block). Refuse to file from memory alone.
2. Root-cause class (best effort from transcript):
   - **detection gap** — detectors scored low / missed pattern
   - **policy gap** — detected but policy allowed / threshold too high
   - **enforcement bug** — policy said escalate/block but gateway returned 200
3. Message `aegis-ceo` with: title, class, transcript excerpt, recommended fix owner (`aegis-gateway` / `aegis-policy-engine` / input-/output-defense), urgency.
4. Append to `memory/findings.md` with delivery status.
5. Trinity report `aegis_redteam.bypass` when available.
