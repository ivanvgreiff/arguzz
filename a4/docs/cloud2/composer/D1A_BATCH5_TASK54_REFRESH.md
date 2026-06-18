# D1.A Task 5.4 — Refresh to n=5 paired triplets + final polish

**Trigger:** seed 1238 jobs landed at 14:01-14:03 CEST (decayepoch on octorand, decayexp on flare). Both completed cleanly (`num_recorded=6000`, log tails show normal kind-count summary).

**Status going in:**
- Both DBs + logs + meta.json already SCP'd to local at `a4/runs/iv_pos_8/d1a/dbs/`
- `validate_d1a_dbs.py` → **10/10 OK** confirmed
- `discover_dbs` now sees `V5=10, V5-decayexp=5, V5-decayepoch=5` (paired triplets: 1234-1238)

**Goal:** refresh all artifacts/plots/notebook/subsection to n=5 paired triplets AND fold in the two remaining follow-up edits (FU-7 hash reproducibility, FU-8 soften Finding C consequence #3). One pass, then close D1.A.

---

## Preview of the refreshed numbers (so you know what to expect)

Opus ran the n=5 paired t-tests directly from the live DBs. Don't take these as final — `build_d1a_artifacts.py` will compute the canonical values — but use them as a sanity gate:

| Metric | Expected refreshed value |
|---|---|
| `n_dbs_v5_static` | 10 (unchanged) |
| `n_dbs_v5_decayexp` | 5 |
| `n_dbs_v5_decayepoch` | 5 |
| `n_paired_seeds` | 5 |
| `paired_seeds` | [1234, 1235, 1236, 1237, 1238] |
| Mean `local_context_final` V5 | 46.40 (unchanged) |
| Mean `local_context_final` V5-decayexp | **46.20** (was 46.00) |
| Mean `local_context_final` V5-decayepoch | **46.40** (was 46.50) |
| Paired p (V5 vs decayexp) | **0.704** (was 0.391) |
| Paired p (V5 vs decayepoch) | **1.000** (unchanged, mean diff still exactly 0) |
| Paired p (decayexp vs decayepoch) | **0.621** (was 0.182) |
| Floor share decayexp post-200 | ~0.48 (essentially unchanged) |
| Epoch staircase shares | 0.96 / 0.48 / 0.48 (essentially unchanged) |

Per-seed paired view (verified live):

| Seed | V5 | V5-decayexp | Δ_exp | V5-decayepoch | Δ_epoch |
|---|---|---|---|---|---|
| 1234 | 46 | 46 | 0 | 46 | 0 |
| 1235 | 46 | 46 | 0 | 47 | +1 |
| 1236 | 46 | 46 | 0 | 47 | +1 |
| 1237 | 48 | 46 | -2 | 46 | -2 |
| **1238 (new)** | **46** | **47** | **+1** | **46** | **0** |

If `build_d1a_artifacts.py` outputs numbers that differ from the above (other than rounding), STOP and investigate before continuing — it means discovery or metrics computation has changed unexpectedly.

---

## Task 5.4 step-by-step

### Step 1 — Re-run the artifact builder

```bash
cd /root/arguzz
python a4/runs/iv_pos_8/d1a/analysis/build_d1a_artifacts.py
```

Sanity checks on the rebuilt artifacts:

| Check | Expected |
|---|---|
| `d1a_metrics_table.csv` | **20 rows** (was 18) — 10 V5 + 5 decayexp + 5 decayepoch |
| `d1a_paired_tests.csv` | **15 rows** (unchanged — 5 metrics × 3 comparisons) |
| `d1a_floor_dynamics.csv` | **~240 rows** (was 202) — added 4 seeds × ~5 buckets × 2-4 modes |
| `d1a_build_summary.json` | `n_paired_seeds=5`, headline numbers match preview above |
| Stdout | "paired seeds: [1234, 1235, 1236, 1237, 1238]" |

### Step 2 — Re-execute the notebook + re-export HTML

```bash
cd /root/arguzz
python a4/runs/iv_pos_8/d1a/analysis/build_d1a_notebook.py --export  # regenerates .ipynb + HTML
# OR if --export wasn't wired, run the two-step:
# python a4/runs/iv_pos_8/d1a/analysis/build_d1a_notebook.py
# jupyter nbconvert --to notebook --execute --inplace a4/runs/iv_pos_8/d1a/IV_POS_8_D1A_NOTEBOOK.ipynb
# jupyter nbconvert --to html a4/runs/iv_pos_8/d1a/IV_POS_8_D1A_NOTEBOOK.ipynb
```

Sanity checks:
- All 5 plot PNGs in `plots/` regenerated (`stat` mtime > 16:30 CEST)
- `.ipynb` outputs cached (file size grew, no `KeyError` / `OperationalError`)
- `.html` regenerated (~950 KB ± 10%)
- Visual check on Plot 2 (cumulative coverage) — V5-decayepoch mean line should now include 5 seeds, with slightly wider std band; the 3 lines should still cluster closely (all within ~1 context unit of each other at n=6000)

### Step 3 — Update `D1A_SUBSECTION.md`

Three rounds of edits:

**3a. Refresh all numbers in TL;DR, Dataset, Headline, Verdict sections.** Specifically:

- TL;DR: change "**4 paired triplets** (seeds 1234–1237, interim; seed 1238 pending)" → "**5 paired triplets** (seeds 1234–1238)"
- TL;DR: change "paired p > 0.39" → "paired p > 0.62"
- Dataset table: remove "+1238 pending" annotation; show seeds 1234-1238 as complete
- Dataset narrative: remove "Task 5.4 will refresh" — replace with "Task 5.4 complete; final n=5"
- Headline numbers: refresh all 6 numbers per the preview table above
- Verdict: refresh p-value citations (0.391 → 0.704; 1.000 unchanged)
- Limitations 1: change "n=4 paired triplets (target n=5 once seed 1238 lands; spec originally n=10)" → "n=5 paired triplets (spec originally n=10; campaign truncated due to POS daemon failure)"
- Limitations 4: change "8 DBs recovered via SSH-bypass; seed 1238 via same pattern" → "all 10 D1.A DBs recovered via SSH-bypass per POS_PLAYBOOK §12.52 (POS daemon was non-responsive; pos_upload never fired)"

**3b. Apply FU-7 (hash reproducibility).** In the Finding C section, replace the bare hash table with a hash table PLUS the reproduction command. Suggested wording:

```markdown
| DB | sha1 of `mode` sequence [200, end) |
|---|---|
| V5-static (all 10 seeds) | `9242c3c47d71dbca` |
| V5-decayexp (all 5 seeds) | `b2bdd9f2986c50b0` |
| V5-decayepoch (all 5 seeds) | `80aa0a00342428be` |

(Hashes computed with the command below; if you get different values, your separator / range convention differs — what matters is that all seeds of a given variant collide on the same hash.)

\`\`\`bash
python -c "
import sqlite3, hashlib, sys
db = sys.argv[1]
with sqlite3.connect(db) as c:
    seq = [m for (m,) in c.execute(
        'SELECT mode FROM bandit_decisions WHERE mutation_id >= 200 ORDER BY mutation_id'
    )]
print(hashlib.sha1('|'.join(seq).encode()).hexdigest()[:16])
" <db_path>
\`\`\`

The collision (all seeds of a variant producing the same hash) is robust to convention choice; the specific hex value is not.
```

**Important:** before you commit these hashes, **actually run** the snippet on one DB per variant and use the values it produces. Opus's three earlier hash sets (`2d14a156…`, `c07da395…`, `32a3abd1…`) and your two earlier sets (`ea856638…/4a18ee31…/b0e23410…` and `9242c3c4…/b2bdd9f2…/80aa0a00…`) disagreed; we still don't know whose convention was used. **Run the exact snippet above** and use those values. If they match your `9242c3c4…` set, great — keep them. If they don't, replace with whatever the snippet produces.

**3c. Apply FU-8 (soften Finding C consequence #3).** In Finding C section, replace the third consequence ("near-zero power" / "even at n=10 the result would still be p≈1.0") with:

```markdown
3. **The current experiment cannot meaningfully distinguish V5-decayepoch from V5-static on `local_context_final` in aggregate**, even at n=5. Per-seed differences are non-zero (Δ ∈ {0, +1, +1, -2, 0}), but the mean diff lands at exactly 0.0 (paired p=1.000). The cancellation is structural, not coincidental: `local_context_final` saturates near mut~2800 (median time_to_46), and the first 2049 mutations are deterministically identical between V5-decayepoch and V5-static (same mode, same floor schedule, same RNG state per seed). Most of the final coverage is therefore inherited from the shared early phase. To meaningfully distinguish them you'd need either (a) **earlier epoch boundaries** (≤1000 instead of 2000/4000) so the staircase fires *inside* the discovery window, or (b) **a metric that saturates later** (e.g., `compressed_global_context_final`, or a coarser CGC grouping per the planned D1.B work).

   For decayexp the situation is different: per-seed Δ_exp ∈ {0, 0, 0, -2, +1}, also no significant aggregate effect (paired p=0.704). Here the limitation isn't shared early phase — it's that K=50 collapses decayexp to `ConstantFloor(0.20)` within ~100 mutations (Finding A), so the variant never actually exercises a gradual decay. A redesigned experiment with K≥500 would be needed to test the intended schedule.
```

### Step 4 — Update provenance in `D1A_SUBSECTION.md`

Update the provenance table:
- `git commit` → new HEAD after this refresh
- `Build date` → today
- All 4 CSV sha256 values → recompute via `hashlib.sha256(open(...,'rb').read()).hexdigest()` after refresh (they will change because content changes)
- `d1a_build_summary.json sha256` → same
- `Notebook` → both `.ipynb` and `.html` (already noted)

### Step 5 — Append final addendum to `D1A_BATCH5_REPORT.md`

Add a final section at the end:

```markdown
---

## Task 5.4 — Final refresh (n=5 paired triplets)

**Date:** YYYY-MM-DD HH:MM CEST
**Commit:** <short hash>

### DBs collected
- `flare_pos_iv_pos_8_d1a_b1c_cTS_semantic_v2_decayexp_seed1238_n6000.db` (cov=47)
- `octorand_pos_iv_pos_8_d1a_b1c_cTS_semantic_v2_decayepoch_seed1238_n6000.db` (cov=46)
- Both pass validate_d1a_dbs.py (10/10 OK)

### Refreshed headline numbers
- Mean local_context_final V5: 46.40 (unchanged)
- Mean local_context_final V5-decayexp: 46.20 (was 46.00)
- Mean local_context_final V5-decayepoch: 46.40 (was 46.50)
- Paired p (V5 vs decayexp): 0.704 (was 0.391)
- Paired p (V5 vs decayepoch): 1.000 (unchanged)
- Floor share decayexp post-200: ~0.48 (unchanged)

### Follow-up edits applied
- FU-7 (hash reproducibility command in Finding C): done
- FU-8 (Finding C consequence #3 softened with n=5 framing): done

### Verdict (final)
Unchanged direction: V5-static remains D2 default. No significant coverage advantage from either decay variant at n=5. Decay variants need redesigned experiments (K≥500 for decayexp; earlier epoch boundaries for decayepoch) to be properly evaluated.

### D1.A status: CLOSED. Ready for parent-report assembly.
```

---

## Pass criteria for Task 5.4

| Check | Required state |
|---|---|
| 10 D1.A DBs + 10 R2 baseline = 20 total in `d1a_metrics_table.csv` | ✓ |
| `n_paired_seeds=5`, `paired_seeds=[1234,1235,1236,1237,1238]` in summary JSON | ✓ |
| Plot files mtime > 16:30 CEST 2026-06-17 (regenerated, not stale) | ✓ |
| `IV_POS_8_D1A_NOTEBOOK.ipynb` + `.html` both regenerated | ✓ |
| `D1A_SUBSECTION.md` references seed 1238 in dataset + headline + verdict | ✓ |
| `D1A_SUBSECTION.md` Finding C hash table values match `python -c "..."` snippet output for at least one DB per variant | ✓ |
| `D1A_SUBSECTION.md` Finding C consequence #3 softened (no "near-zero power" / "even at n=10" claims) | ✓ |
| `D1A_BATCH5_REPORT.md` has Task 5.4 addendum appended | ✓ |
| No git commit | (Opus/Ivan review first) |

---

## OUT OF SCOPE

| Out of scope | Why |
|---|---|
| Dispatching more seeds (1239-1243 × decay variants) | Spec scope locked at n=5; further work requires a redesigned experiment |
| Modifying `build_d1a_artifacts.py` other than to verify it runs cleanly | Already correct; FU-4/FU-5 were one-off edits, no more needed |
| Touching `build_d1a_notebook.py` other than to re-execute | Already correct |
| Investigating WHY ConstrainedTSScheduler mode is seed-independent | Out of scope for D1.A; flag in Finding C and move on |
| `git commit` / `git push` | Opus + Ivan review first |
| Drafting `IV_POS_8_D1_REPORT_FOR_PRO.md` (parent report) | Opus drafts after D1.B + D1.C also complete |

---

## When done

Report back with:
1. Refreshed headline numbers (confirm they match preview ± rounding)
2. The Finding C hash values that the snippet actually produced (so we can stop chasing the hash discrepancy)
3. Confirmation all 5 plots regenerated + notebook re-executed
4. Path to refreshed HTML notebook
5. Final D1.A verdict: **CLOSED** (or HALT with reason if anything anomalous)
