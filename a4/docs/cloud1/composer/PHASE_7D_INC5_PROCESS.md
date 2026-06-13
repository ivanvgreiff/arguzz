# Phase 7d Inc 5 — Process plan (no thrashing edition)

**From:** Opus
**To:** User + Composer
**Purpose:** Eliminate the back-and-forth that plagued Inc 4. The next increment runs as a single contract.

## What we are NOT doing this time

| Inc 4 anti-pattern | Inc 5 replacement |
|---|---|
| Discover POS playbook fact wrong → correct → re-dispatch | **Lock playbook + canonical templates at handoff time.** No new POS commands or env vars without explicit work-order amendment. |
| Discover `dispatch_pos.py` bug mid-dispatch (5 jobs / 1 node) | **Use `dispatch_audit.sh` only** (covers single + multi mode). No raw `dispatch_pos.py` calls in the runbook. |
| `pos allocations free` trims calendar | **Always `-k`.** Already in §12.43 + playbook header callout + handoff. Composer should never type `pos allocations free` without `-k`. |
| Hardware flakiness (polynize) bricks the orchestrator | **Pre-allocate 6 nodes for any 5-job campaign** (1 spare). `dispatch_audit.sh` should be able to substitute on failure (Inc 5 enhancement, see §3 below). |
| POS coordinator rc=255 false-failure stops the suite | **Patched orchestrator + collect script** (Inc 4 PM). Already in place. Inc 5 inherits. |
| collect script misses results uploaded via `pos_upload` | **Patched collect script** (Inc 4 PM). Already in place. |
| B1 verifier raw fails treated as new failures | **`B1_apply_disposition.py`** runs automatically as part of every B1 collection. Already in place. |
| Discover failure during user-Opus chat → another round of fixes | **Pre-flight script catches known failure modes BEFORE dispatch** (see §4). |
| Composer reports incremental status; user/Opus must follow up | **Composer reports ONCE at the end** with a full artifact list, OR raises a blocker. No "should I do X next?" pings. |

## The Inc 5 contract (single document)

**Inc 5 = E5 evidence pack: 48 markdown files (one per kept arm) showing concrete per-arm correctness evidence.**

Format will be:
1. **§1 Work order** — Opus writes one document (≤5 pages) covering:
   - Exact list of artifacts to produce (48 `.md` files + 1 index + 1 summary JSON)
   - Exact list of dependent data sources (which DBs to read from)
   - Exact list of scripts to use (E5 generator, B1 verifier output, B4 traceability dataframe)
   - Acceptance gate (every `.md` file produced; zero arms with `INCORRECT` verdict; index `OK`)
   - Failure modes + recovery for each step
   - **Single command** to execute the full pipeline end-to-end
2. **§2 Pre-flight** — Composer runs `inc5_preflight.py`:
   - Checks all dependent data sources exist
   - Checks all scripts present + executable
   - Checks POS allocation + calendar (if needed)
   - Checks disk space, bundle freshness, etc.
   - **Exits nonzero with explicit failure list** if anything is missing
3. **§3 Execute** — Composer runs the single pipeline command:
   ```bash
   bash a4/audits/inc5_e5_pipeline.sh
   ```
   which does: data prep → E5 generation (48 jobs) → verification → index build → JSON summary → acceptance gate check
4. **§4 Report** — Composer pings ONCE with the final artifact list + verdict OR a blocker

## Inc 5 implementation backlog (pre-launch work for Opus)

Before launching Inc 5, the following needs to exist:

| Artifact | Purpose | Status |
|---|---|---|
| `a4/docs/cloud1/composer/PHASE_7D_INC5_WORK.md` | The work order for Composer | Opus drafts after Inc 4 closeout |
| `a4/audits/inc5_preflight.py` | Pre-flight script (§2 above) | Opus drafts |
| `a4/audits/E5_per_arm_evidence.py` | The 48-arm evidence generator (the actual work — D44 in decisions) | Opus + Composer co-design |
| `a4/audits/inc5_e5_pipeline.sh` | Single-command driver | Opus drafts |
| `a4/audits/B1_apply_disposition.py` | (Already exists from Inc 4) — reused for any B1 results E5 references | Done |
| Patched `dispatch_audit.sh`, `collect_*_results.sh`, `run_*_b1_verify_pos.sh` | (Already exists from Inc 4) — reused if Inc 5 needs new POS dispatches | Done |

E5 is mostly WSL work (reads existing POS DBs, runs the verifier per-arm, generates markdown). If E5 needs any NEW POS runs (e.g. to fill missing per-arm coverage), those will be in the work order with explicit manifest + command.

## Inc 5 launch checklist for Composer

When the work order is handed off, Composer's response sequence is:

```
□ Read PHASE_7D_INC5_WORK.md end-to-end
□ Run a4/audits/inc5_preflight.py — fix any gaps before proceeding
□ Run bash a4/audits/inc5_e5_pipeline.sh
□ Wait for pipeline to complete (it logs everything to inc5_run.log)
□ Verify acceptance gate output (gate prints OK/FAIL at the end)
□ If POS allocation was used: pos allocations free -k <alloc>
□ Single commit of all generated artifacts + any code/data fixes
□ Ping Opus ONCE with: "Inc 5 complete. 48/48 arms verified. Gate: OK. Commit <sha>. Anomalies: <list or 'none'>."
```

Composer does NOT ping Opus between steps. Composer does NOT ask "should I do X?" — the work order has the answer or it's a bug in the work order, in which case Composer flags it as a blocker.

## What about new bugs we haven't anticipated?

If the pipeline fails on a NEW bug (something not handled by the patches/scripts), Composer:

1. Captures the failure (log, stack trace, partial outputs)
2. Stops the pipeline
3. Pings Opus with: "Blocker: <one-paragraph description + log location>. Pipeline halted at step X of Y. POS resources state: <held/freed>. Awaiting decision."
4. Does NOT attempt to fix the bug itself unless the fix is trivial and obvious (e.g. a typo in a path).

This keeps the back-and-forth to ONE round per genuinely-new issue, instead of N rounds for issues we should have anticipated.
