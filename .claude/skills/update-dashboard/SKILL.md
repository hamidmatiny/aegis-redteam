---
name: update-dashboard
description: Publish the red-team dashboard from the corpus. Headline is unique open vectors right now; numbers come from a script, never from findings.md or by hand.
allowed-tools: Bash, mcp__trinity__list_channel_groups, mcp__trinity__send_group_message
---
# /update-dashboard

The numbers come from `scripts/dashboard.py`. You publish them. You do not count, estimate, or restate them.

## Do this

1. Run `python3 scripts/dashboard.py --write` from the repo root. It reads `memory/attack-corpus.jsonl`,
   rewrites `dashboard.yaml`, and prints the post.
2. Post that output verbatim to the team's Slack group with `mcp__trinity__send_group_message`, under the
   heading `*[AEGIS Redteam] Dashboard — <UTC date>*`.

## What the numbers mean (do not redefine them)

- **Unique open vectors right now** — distinct prompts whose *latest live gateway retest* returned 200.
  This is the headline and the only measure of current exposure. A vector marked STALE has had no retest
  in 7 days; retest it in the next batch instead of reporting it as confirmed.
- **Benign controls blocked right now** — false positives. Report them as a defect, never as a win.
- **Retest rows** — repeat tests of known prompts. Never add them to a bypass count.
- **History** — all-time rows including retests. Label it as history. Never present it as a bypass rate.

## Do not

- Do not read status from `memory/findings.md`. That file is the narrative; the corpus is the status.
- Do not call a finding closed because a *different* prompt in its family returned 403. Status is per exact prompt.
- Do not report "approved" or "PR pending" unless you can cite the PR URL or the operator-queue response.
