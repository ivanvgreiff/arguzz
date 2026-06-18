# D1.C Batch 2 — Composer Kickoff

**Branch:** `cloud2`
**Spec:** [`IV_POS_8_D1_C_SPEC.md`](../IV_POS_8_D1_C_SPEC.md) v0.3 §2.2 (LOCKED)
**Parent plan:** [`IV_POS_8_D1_REVISIT_PLAN.md`](../IV_POS_8_D1_REVISIT_PLAN.md) v0.6 §3.2 + §3.2.1
**Predecessor:** D1.C Batch 1 ACCEPTED 2026-06-17 by Ivan/Opus (uncommitted; will squash with Batches 2+3); 16/16 pass criteria green, 20 unit tests, 515 standalone tests passing. See [`D1C_BATCH1_REPORT.md`](./D1C_BATCH1_REPORT.md).
**Issued by:** Ivan, on Opus's recommendation
**Expected effort:** ~1.5–2 days (8 Tier-2 functions are more involved than Tier-1 — graph construction, SQL, Cat-B NULL handling)

---

## TL;DR for Composer

Implement Batch 2 of D1.C as defined in spec v0.3 §2.2. This is the **8 Tier-2 per-campaign metric implementations + 15-row paired-decay tests + 30 × 8 metrics CSV + `d1c_tier2_schema.md` D2.G coordination artifact**. Still analysis-only — no production code edits.

> **Read Batch 1's report first** ([`D1C_BATCH1_REPORT.md`](./D1C_BATCH1_REPORT.md)) — Batch 1's empirical findings inform Batch 2's expected sanity ranges and a few carry-forward items below.

**The single hardest constraint: `pro_s5_co_failure_graph_degree_distribution` is the only expensive Tier-2 metric.** Build a co-failure graph from the `failures` table: nodes = distinct `constraint_loc`, edges = pairs that co-failed in any single mutation. For a 6000-mut DB with ~150 distinct constraint_locs and ~3 average failures per pull, the graph has at most ~150 × 149 / 2 = 11,175 edges. Build it ONCE per DB, not per metric. If memory or compute becomes an issue, document and scope to a sub-sample, but the spec's expected scale (30 DBs × 150 nodes × O(n²) edges) is well within Python+sqlite limits.

**Carry-forward items from Batch 1 review** (Opus flagged):
1. **Rename `build_batch1_audit.py` → `build_d1c_batch1_audit.py`** to eliminate the cross-script name collision with D1.B's same-named script (D1.C imports `cat_a_db_list` from D1.B via `sys.path.insert`; safe today, fragile tomorrow). Update internal references in test fixtures + report.
2. **Batch 3 will need multi-threshold analysis** for `recent_marginal_discovery_rate` per spec §1.3.2 (25th / 50th / 75th percentile thresholds). NOT in Batch 2 scope, but noted here so you don't accidentally drop the multi-threshold tracking from `bug_proximity.py`.
3. **f_new_flag empirical near-deadness** (Batch 1 audit: ~0.17% full / ~0% post-local) is a known finding; Batch 3 shortlist will route it to Bucket B per the §1.3.4 non-saturation gate. Batch 2 does NOT need to do anything about this; just don't be surprised by it.

---

## Scope (exactly what Batch 2 ships)

| File | Action | Rough size |
|---|---|---|
| `a4/runs/iv_pos_7/analysis/bug_proximity.py` | Replace 8 `NotImplementedError` stubs with Tier-2 function bodies per spec §1.2 + §2.2. NEW helpers: `_load_co_failure_graph(conn) -> dict[str, set[str]]` (build once per DB; reused across metrics that need degree distributions); `_iter_d_loc_or_d_glob(conn) -> Iterator[tuple[int, int]]` (single-pass mutation_rewards scan). | +250–350 LOC delta |
| `a4/runs/iv_pos_7/analysis/test_bug_proximity.py` | Add ≥12 new tests covering each Tier-2 metric on synthetic mini-DBs + Cat-B NULL handling + co-failure graph edge cases (disconnected components, empty graph). | +200–300 LOC delta |
| `a4/runs/iv_pos_8/d1c/analysis/build_d1c_batch1_audit.py` | **RENAME** from `build_batch1_audit.py` (was Batch 1's filename). Update `import` lines + docstring header. | rename + small edits |
| `a4/runs/iv_pos_8/d1c/analysis/build_d1c_artifacts.py` | **NEW.** Script: for each of 30 Cat-A DBs, compute all 8 Tier-2 metrics; emit `d1c_metrics_table.csv` (30 rows × 8 metric columns + 3 provenance columns: corpus/variant/seed); emit `d1c_paired_tests.csv` (paired t-tests on 15-row decay-paired subset for each of 8 metrics); emit `d1c_unpaired_means.csv` (V5-static unpaired rows 1239–1243 for mean/variance comparison). Provenance header row with Pro-§ mapping per spec §2.2 task 2. | ~200 LOC |
| `a4/runs/iv_pos_8/d1c/d1c_metrics_table.csv` | **NEW artifact.** 30 rows × 11 columns (3 provenance + 8 metric); `cat_a_*` / `cat_b_*` prefix on metric columns; Cat-B columns NULL on R2 V1/V5 rows | data |
| `a4/runs/iv_pos_8/d1c/d1c_paired_tests.csv` | **NEW artifact.** Per Tier-2 metric × paired comparison (V5-static vs decayexp; V5-static vs decayepoch; decayexp vs decayepoch) on the 5-paired-triple subset | data |
| `a4/runs/iv_pos_8/d1c/d1c_unpaired_means.csv` | **NEW artifact.** V5-static rows 1239–1243 per Tier-2 metric (mean, std) | data |
| `a4/runs/iv_pos_8/d1c/d1c_tier2_schema.md` | **NEW.** D2.G coordination artifact — column-name + dtype + Pro-§ reference + Cat-A/B label for all 8 Tier-2 metrics. Cross-link from `IV_POS_8_D2_PLAN.md` D2.G section (Composer adds the cross-link). | ~1–2 pages |
| `a4/docs/cloud2/composer/D1C_BATCH2_REPORT.md` | **NEW.** Composer report per workflow §5 below | ~3–5 pages |
| `a4/docs/cloud2/IV_POS_8_D2_PLAN.md` | **MINIMAL EDIT.** Add one bullet under D2.G section: "D2.G's `build_d2_artifacts.py` consumes columns prefixed `cat_a_pro_s*` from `d1c_metrics_table.csv` per `d1c_tier2_schema.md`." | +1 line |

**Total expected delta:** ~700–900 LOC across 4 source files + 4 data/schema/report artifacts. ~1.5–2 days at Batch 1 pace.

## NOT in Batch 2 (deferred to Batch 3)

- **Cross-correlation analysis** (`build_d1c_correlation_analysis.py`) — Batch 3
- **Tier-1 shortlist composition** (`d1c_signal_shortlist.md`) — Batch 3
- **D1.E L1 hand-off** (`d1e_handoff_L1_signals.md`) — Batch 3
- **Pro-facing subsection** (`D1C_SUBSECTION.md`) — Batch 3
- **D1.C notebook** (`IV_POS_8_D1C_NOTEBOOK.ipynb` + `.html`) — Batch 3
- **Multi-threshold analysis for `recent_marginal_discovery_rate`** — Batch 3 (per spec §1.3.2)
- **Conditional Batch 1.5 Option C replay** — only triggered if Batch 3 cross-correlation finds all 4 non-trivial Tier-1 signals fail orthogonality
- **Any production-code edits** — analysis-only by spec §3

If you find yourself touching any of the above, stop and confirm with Ivan before continuing.

---

## Tier-2 metric implementation notes (spec §1.2 + §2.2)

### Metric 1: `pro_s5_verifier_accepted_invalid_count` (Cat-A)

**SQL (ALIGNED with `IV_POS_8_D1_A_SPEC.md:539` locked definition — DO NOT use the Pro Report 3 §5-literal Cat-B variant; that's reserved for a later revision):**

```sql
SELECT COUNT(*) FROM mutations WHERE verifier_accepted=1 AND num_failures>0
```

Returns: int.

### Metric 2: `pro_s5_co_failure_graph_degree_distribution` (Cat-A) — the expensive one

**Graph construction:**
```python
def _load_co_failure_graph(conn) -> dict[str, set[str]]:
    """Return adj[constraint_loc] = {co-failing constraint_locs across the campaign}."""
    grouped: dict[int, list[str]] = defaultdict(list)
    for mid, loc in conn.execute("SELECT mutation_id, constraint_loc FROM failures"):
        grouped[mid].append(loc)
    adj: dict[str, set[str]] = defaultdict(set)
    for locs in grouped.values():
        for i in range(len(locs)):
            for j in range(i+1, len(locs)):
                adj[locs[i]].add(locs[j])
                adj[locs[j]].add(locs[i])
    return adj
```

**Distribution:** `{mean, median, p95, p99, density}` where:
- degree = `len(adj[loc])` per node
- density = `2 * |edges| / (|nodes| * (|nodes| - 1))` (handle |nodes| ≤ 1 → 0.0)

Returns: dict.

### Metric 3: `pro_s5_singleton_failure_rate` (Cat-A)

```sql
SELECT
  SUM(CASE WHEN cnt = 1 THEN 1 ELSE 0 END) * 1.0 /
  COUNT(*) AS rate
FROM (
  SELECT mutation_id, COUNT(*) AS cnt
  FROM failures
  GROUP BY mutation_id
)
```

Returns: float in `[0, 1]`.

### Metric 4: `pro_s5_d_loc_distribution` (Cat-A)

`{mean, median, p95, p99}` of `mutation_rewards.d_loc` across all rows.

Use `numpy.percentile` or pure-Python `statistics`.

Returns: dict.

### Metric 5: `pro_s8_unique_locs_with_d_loc_le_2` (Cat-A)

```sql
SELECT COUNT(DISTINCT f.constraint_loc)
FROM failures f
JOIN mutation_rewards mr ON mr.mutation_id = f.mutation_id
WHERE mr.d_loc <= 2
```

Returns: int.

### Metric 6: `pro_s8_unique_locs_with_d_glob_le_1` (Cat-A) — **Pro §8 paired with Metric 5**

```sql
SELECT COUNT(DISTINCT f.constraint_loc)
FROM failures f
JOIN mutation_rewards mr ON mr.mutation_id = f.mutation_id
WHERE mr.d_glob <= 1
```

Returns: int.

### Metric 7: `pro_s5_proof_generated_zero_residue_rejected_rate` (Cat-B; D1.A 10 DBs only)

```sql
SELECT
  COUNT(*) FILTER (WHERE m.proof_generated = 1 AND mr.d_glob = 0 AND m.proof_verify_failed = 1) * 1.0 /
  COUNT(*) AS rate
FROM mutations m
JOIN mutation_rewards mr ON mr.mutation_id = m.id
WHERE m.proof_generated IS NOT NULL
```

**Returns None** if `proof_generated` column is NULL across the campaign (R2 V1/V5 DBs). Use `(d_glob = 0)` as the "family_residues all zero" heuristic per spec §2.2 task 1.

### Metric 8: `pro_b_wall_clock_per_normalized_discovery` (Cat-B; D1.A 10 DBs only)

```python
local_context_final = read_from_analysis_metrics(db_path)  # existing helper
mean_elapsed_ms = SELECT AVG(elapsed_ms) FROM mutations WHERE elapsed_ms IS NOT NULL
if mean_elapsed_ms is None or local_context_final == 0:
    return None
return mean_elapsed_ms / local_context_final
```

Returns: Optional[float].

---

## `d1c_tier2_schema.md` requirements (D2.G coordination)

Single markdown file with this exact structure per spec §2.2 task 3:

```markdown
# D1.C Tier-2 schema (for D2.G consumption)

**Source CSV:** `a4/runs/iv_pos_8/d1c/d1c_metrics_table.csv`
**Corpus:** 30 Cat-A DBs (`cat_a_db_list()`) — 10 R2 V1 + 10 R2 V5 + 10 D1.A decay
**Spec lock:** `IV_POS_8_D1_C_SPEC.md` v0.3 §1.2 + §2.2 task 1

## Schema

| Column | dtype | Pro reference | Category | NULL on | Notes |
|---|---|---|---|---|---|
| `corpus` | str | n/a | provenance | n/a | one of {V1, V5, D1A} |
| `variant` | str | n/a | provenance | n/a | one of {V1, V5, V5_decayexp, V5_decayepoch} |
| `seed` | int | n/a | provenance | n/a | |
| `cat_a_pro_s5_verifier_accepted_invalid_count` | int | Pro §5 | A | (never) | aligned to D1.A spec :539 SQL |
| `cat_a_pro_s5_co_failure_graph_degree_p95` | float | Pro §5 | A | (never) | p95 of degree distribution (Composer: pick ONE percentile to expose as a column; full distribution lives in a separate dict, not in this CSV) |
| `cat_a_pro_s5_singleton_failure_rate` | float | Pro §5 | A | (never) | ∈ [0, 1] |
| `cat_a_pro_s5_d_loc_p95` | int | Pro §5 / §8 | A | (never) | p95 of mutation_rewards.d_loc |
| `cat_a_pro_s8_unique_locs_with_d_loc_le_2` | int | Pro §8 | A | (never) | ≤ local_context_final |
| `cat_a_pro_s8_unique_locs_with_d_glob_le_1` | int | Pro §8 | A | (never) | ≤ local_context_final |
| `cat_b_pro_s5_proof_generated_zero_residue_rejected_rate` | float \| null | Pro §5 | B | R2 V1, R2 V5 (no proof columns) | ∈ [0, 1] when present |
| `cat_b_pro_b_wall_clock_per_normalized_discovery` | float \| null | Revisit plan :160 | B | R2 V1, R2 V5 (no elapsed_ms) | ms / discovery |

## D2.G usage

D2.G's `build_d2_artifacts.py` reads this CSV and computes the V5-vs-V6 comparison table.
Cat-A columns are populated on all 30 DBs; Cat-B columns are populated on the 10 D1.A DBs only.
```

The CSV must be consumable as-is by D2.G — column names must EXACTLY match `cat_a_pro_s*` / `cat_b_pro_*` patterns.

---

## Workflow

1. **Read the spec end-to-end first.** Particularly:
   - §1.2 Tier-2 function signatures + docstring conventions
   - §1.3.5 Cat-A vs Cat-B labeling convention (`cat_a_*` / `cat_b_*` column prefix)
   - §2.2 Batch 2 task list (your scope)
   - §3 risk table (especially the `co_failure_graph` degeneracy risk and Cat-B NULL handling)
   - Review the Batch 1 report's §10 deviations to understand the carry-forward items
2. **Open ONE PR for Batch 2**, squash-mergeable to `cloud2`. Branch name: `cloud2-d1c-batch2-tier2-metrics`.
3. **Implementation order (recommended):**
   1. Rename `build_batch1_audit.py` → `build_d1c_batch1_audit.py` first (smallest mechanical change; eliminates the cross-script collision risk before touching anything else); update test fixture imports + Batch 1 report cross-references
   2. `_load_co_failure_graph()` helper — write once, test on synthetic mini-DB (disconnected components, single node, empty graph)
   3. Tier-2 metric bodies one at a time in §1.2 order; each gets a 1-line `NotImplementedError` removal + 30-line body + 1–2 tests
   4. Cat-B metrics last (require `proof_generated` / `elapsed_ms` NULL handling)
   5. `build_d1c_artifacts.py` — assemble the 3 output CSVs
   6. `d1c_tier2_schema.md` — fill in the template above with actual dtypes from the CSV
   7. Edit `IV_POS_8_D2_PLAN.md` D2.G section: add the 1-line cross-link
   8. `D1C_BATCH2_REPORT.md`
4. **Self-checkpoint:** before submitting, run:
   - `pytest a4/runs/iv_pos_7/analysis/test_bug_proximity.py -q` — must show ≥32 tests (Batch 1's 20 + ≥12 new)
   - `pytest a4/standalone/tests/ -q` — must stay green (no regressions; ~515 standalone)
   - Open `d1c_metrics_table.csv` in pandas, verify `df.shape == (30, 11)`, Cat-B columns are NaN on the 20 R2 rows and float on the 10 D1.A rows
5. **Write a Batch 2 report** (`composer/D1C_BATCH2_REPORT.md`) covering:
   - What you actually changed (with LOC counts per file)
   - Any deviations from the spec (and why)
   - 2–3 sentence descriptive summary of what the Tier-2 metrics show across V1 vs V5 vs decay — do NOT pre-judge whether decay variants are "significant" (paired tests in `d1c_paired_tests.csv` are the formal answer)
   - Test results (count + any flakes)
   - Cat-B NULL handling spot-check (paste one R2 row + one D1.A row from `d1c_metrics_table.csv`)
   - Co-failure graph descriptive stats on V5 s1234 (n_nodes, n_edges, density, degree p95) — sanity check
   - Confirmation that NO production-code files were touched (`git diff cloud2 -- a4/standalone/ | head`)

---

## Pass criteria (Batch 2 ships)

- [ ] `build_batch1_audit.py` renamed to `build_d1c_batch1_audit.py`; all imports updated; tests still pass
- [ ] 8 Tier-2 functions implemented (no `NotImplementedError` stubs remain in `bug_proximity.py`)
- [ ] `_load_co_failure_graph()` helper exists; reused by metrics that need degree distribution (single graph build per DB, not per metric)
- [ ] All 8 Tier-2 functions have Cat-A/B docstring tag, Pro Report 3 §X reference, source-table reference, computational-cost note, return-type
- [ ] `pro_s5_verifier_accepted_invalid_count` SQL matches `IV_POS_8_D1_A_SPEC.md:539` (cite file:line in test docstring per spec §2.2 task 4)
- [ ] Cat-B metrics return None when columns NULL (test on synthetic R2-style DB without proof columns)
- [ ] `test_bug_proximity.py` has ≥12 new tests (≥32 total); all green
- [ ] `d1c_metrics_table.csv` exists with shape (30, 11); Cat-B columns NaN on 20 R2 rows + float on 10 D1.A rows
- [ ] `d1c_paired_tests.csv` exists with paired t-tests on 15-row decay-paired subset (5 V5-static-paired + 5 decayexp + 5 decayepoch on seeds 1234-1238) for each of 8 metrics
- [ ] `d1c_unpaired_means.csv` exists with V5-static rows 1239-1243 (5 rows × 8 metric mean/std)
- [ ] `d1c_tier2_schema.md` written with all 11 columns documented (3 provenance + 8 metric) + D2.G usage note
- [ ] `IV_POS_8_D2_PLAN.md` D2.G section has the 1-line cross-link to `d1c_tier2_schema.md`
- [ ] Sanity invariants pass:
  - For every DB: `cat_a_pro_s5_singleton_failure_rate ∈ [0, 1]`
  - For every DB: `cat_a_pro_s5_d_loc_p95 ≥ median(d_loc)` (degenerate to equality if distribution is degenerate)
  - For every DB: `cat_a_pro_s8_unique_locs_with_d_loc_le_2 ≤ local_context_final` (subset of total locs)
  - For every DB: `cat_a_pro_s8_unique_locs_with_d_glob_le_1 ≤ local_context_final`
  - For R2 V1/V5 DBs: Cat-B columns are NaN
  - For D1.A DBs: Cat-B columns are float (potentially 0.0 but not NaN)
- [ ] Full standalone pytest sweep still green (no regressions; ~515 standalone)
- [ ] `git diff cloud2 -- a4/standalone/` shows ZERO changes
- [ ] `D1C_BATCH2_REPORT.md` written per workflow step 5

---

## Where to look for help

| Question | Where to look |
|---|---|
| What is `local_context_final` and where do I read it from? | `a4/runs/iv_pos_7/analysis/metrics.py` — `local_context_final` is the production metric; reuse the existing helper |
| What does the D1.A `verifier_accepted_invalid` SQL look like? | `IV_POS_8_D1_A_SPEC.md:539` (cited in spec §1.2) |
| What's the Cat-B column situation on R2 DBs? | Spec §1.1: `mutations.proof_generated`, `mutations.proof_verify_failed`, `mutations.elapsed_ms` are NULL on R2; only D1.A's 10 new DBs populate them. Composer Batch 1 verified this on R2 V5 s1234. |
| What's the paired-test convention? Same as D1.A/D1.B? | Yes — `scipy.stats.ttest_rel` on seed-matched arrays. D1.A and D1.B already use this; copy the helper if convenient. |
| Co-failure graph too big to fit in memory? | Spec §3 risk table — expected scale ~150 nodes / ~11K edges per DB is fine. If you hit memory pressure, document and ask. |
| Where do I import `cat_a_db_list` from after the rename? | After Composer renames the script, the new path is `a4/runs/iv_pos_8/d1c/analysis/build_d1c_batch1_audit.py`. D1.B's `build_batch1_audit.py` (the original) keeps its name and is the source of truth for `cat_a_db_list`. So D1.C's NEW script can keep importing from D1.B; the rename is only for D1.C's own audit script. |

---

## Hand-off statement (paste this when delegating to Composer)

> Implement D1.C Batch 2 per the locked spec at `a4/docs/cloud2/IV_POS_8_D1_C_SPEC.md` v0.3 §2.2. Follow the workflow in `a4/docs/cloud2/composer/D1C_BATCH2_COMPOSER_KICKOFF.md`. Open one PR against `cloud2` named `cloud2-d1c-batch2-tier2-metrics`. **D1.C is still analysis-only — touch nothing under `a4/standalone/`.** First task: rename `a4/runs/iv_pos_8/d1c/analysis/build_batch1_audit.py` → `build_d1c_batch1_audit.py` per Opus's Batch 1 review (cross-script collision risk). Stop and ask before touching anything outside the Batch 2 scope listed in the kickoff. Pass criteria are the 15 checkboxes in the kickoff doc. Submit your work as a single PR plus a written report at `a4/docs/cloud2/composer/D1C_BATCH2_REPORT.md`.

---

*End of D1.C Batch 2 kickoff.*
