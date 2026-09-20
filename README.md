# AEGIS Redteam

Personal-fleet adversarial agent that continuously attacks the **live** AEGIS gateway and escalates confirmed bypasses to `aegis-ceo`.

## Skills

| Skill | Purpose |
|-------|---------|
| `/attack-gateway` | Live attack batch + corpus log |
| `/ingest-technique` | Protocol D technique handoff |
| `/file-bypass` | Package bypass for CEO decision |

## Target

`POST https://defenseaegis.org/v1/chat/completions` — full defense pipeline.

## Docs

- Protocol D: `aegis-infra/docs/a2a-routing.md`
- Org chart: `aegis-infra/docs/org-chart.md`
- Seed audit: `memory/seed-audit-2026-09-20.md`
