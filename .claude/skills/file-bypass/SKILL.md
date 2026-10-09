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
4. **Get the ID from the registry, never pick one.** Run
   `python3 scripts/finding_ids.py assign --corpus-id <corpus row id> --title "<title>" --family <family> [--variant-of BYPASS-NNN]`
   and use the `id` it prints. The same exact prompt always returns its existing ID. A different prompt always gets a new
   one: a reworded variant of a known finding passes `--variant-of` and still gets its own number. Never write
   `BYPASS-NNN` for a prompt the registry did not return that ID for (on 2026-10-09 a batch reused BYPASS-006, which is
   Log4j, for a TOML prompt). Tag the corpus row with `"finding_id"`.
5. Append to `memory/findings.md` under that ID, with delivery status. Approval, authorization or "PR pending" must
   cite a PR URL or an operator-queue response ID (see CLAUDE.md). Otherwise write "not approved".
6. Run `python3 scripts/finding_ids.py check`. It must print 0 problems before you post or report the finding.
7. Trinity report `aegis_redteam.bypass` when available.
