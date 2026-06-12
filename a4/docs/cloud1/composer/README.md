# Composer's working folder

This folder is for **Composer's own working notes and per-phase implementation summaries**.

## Hard rules for Composer (read carefully)

1. **You MAY create or edit any file under `a4/docs/cloud1/composer/`.** This is your sandbox.
2. **You MAY NOT edit any of these files**, all of which are owned by Opus:
   - `a4/docs/cloud1/CLOUD1_AGENT_ONBOARDING.md`
   - `a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md`
   - `a4/docs/cloud1/CLOUD1_IMPLEMENTATION_PLAN.md`
   - `a4/docs/cloud1/CLOUD1_STATUS.md`
   - `a4/docs/cloud1/ProG_Report_2.md`
   - Any file under `a4/docs/cloud1/phases/PHASE_*.md`
   - Any file under `a4/docs/precloud/`
   - Any file under `a4/runs/iv_pos_5/`
3. **When you finish a phase, write your implementation summary to `a4/docs/cloud1/composer/PHASE_N_COMPOSER_SUMMARY.md`** using the template below.
4. **Opus will read your summary and write the OFFICIAL phase retrospective** to `a4/docs/cloud1/phases/PHASE_N_*.md` after reviewing your code.
5. **Any new D-decision you want to propose goes in `a4/docs/cloud1/composer/PROPOSED_DECISIONS.md`** — Opus will move them into `CLOUD1_DECISIONS_FOR_PRO_R2.md` after review.

## Template for `PHASE_N_COMPOSER_SUMMARY.md`

Copy-paste this and fill it in honestly. Opus uses it during review.

```markdown
# Phase N — Composer Implementation Summary

**Status**: ✅ implementation complete; awaiting Opus review
**Date**: <YYYY-MM-DD>
**Effort**: <hours / sessions>

## 1. What I built (1-2 paragraphs)

<Describe the code you wrote and the test approach in plain English. Do not summarize
ProG_Report_2.md or restate the plan — just describe what landed.>

## 2. Files I touched

| File | Δ (new / edit / delete) | LOC change | What |
|------|--------------------------|------------|------|
| `path/to/file.py` | new | +120 | <one-line summary> |
| `path/to/other.py` | edit | +15 / -3 | <summary> |

## 3. Test results

\```
$ python -m pytest path/to/new/tests.py -v
<paste output>
\```

\```
$ <full fast suite cmd>
<paste output>
\```

## 4. Choices I had to make (and why)

For each non-obvious choice you made that wasn't in the plan or ProG_Report_2.md:

- **Choice**: <e.g. "I made `reward_v2` return a NamedTuple instead of a dict because ...">
- **Alternatives I considered**: <e.g. "dict, dataclass">
- **Reasoning**: <why this choice>
- **Risk if wrong**: <how hard to revert>
- **Should this be a D-decision?**: yes / no / unsure

## 5. Things I'm uncertain about

List anything you'd want Opus to double-check. Be honest — Opus will catch unflagged
issues anyway, but pre-flagging speeds up review.

## 6. Anything I noticed while reading the codebase

Bugs, inconsistencies, stale docs, etc. — Opus appreciates these notes even if you
didn't fix them. Do NOT fix them yourself; raise them here for triage.

## 7. Open questions for Opus

Specific questions that need an answer before Phase N+1.
```

## Workflow at a glance

```text
1. Opus writes a phase doc in a4/docs/cloud1/phases/PHASE_N_*.md (tasks, exit criteria)
2. Composer reads CLOUD1_AGENT_ONBOARDING.md + the phase doc + cited Pro sections
3. Composer implements code + tests in a4/standalone/
4. Composer writes PHASE_N_COMPOSER_SUMMARY.md here in this folder
5. Composer pings Opus / human handoff
6. Opus reviews:
   - reads Composer's code line-by-line
   - reads Composer's summary
   - thinks through "what would I have done?" and compares
   - either approves OR files a follow-up TODO for Composer
7. After approval, Opus writes the OFFICIAL retrospective in a4/docs/cloud1/phases/
   and updates CLOUD1_STATUS.md / CLOUD1_DECISIONS_FOR_PRO_R2.md as needed
```

Why this separation? So the audit trail has two voices: Composer's "here's what I did" and Opus's "here's what passed review". If they diverge, the difference is the value Opus added.
