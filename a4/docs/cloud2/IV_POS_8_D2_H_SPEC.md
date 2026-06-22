# IV.POS.8 — Preliminary Spec: D2.H — Constraint-space exploration notebook + report

**Version:** v0.1 — **PRELIMINARY / DRAFT FOR IVAN REVIEW** (authored by Opus-CP acting as D2-Opus, 2026-06-21).
**Phase:** New_Master Phase 4-adjacent — **runs after D2.G**, consumes its CSVs + the campaign DBs. The Pro-facing **exploration-effectiveness** artifact (notebook + report), modeled on the D1/V6 notebooks that fed ProG_Report_3.
**Motivation (Ivan):** *"For the D1/V6 work I gave Pro a notebook + report showing how well our variants explore the constraint space. We have most of that logic. We need it for the current POS campaign — especially coverage curves and the loc/CGC sets each variant finds, including the exclusive sets — plus whatever else demonstrates each architecture's effectiveness at exploring the constraint space (hypothesized to surface underconstraints)."*
**Thesis it serves:** *broader/deeper constraint-space exploration → higher chance of probing an under-constrained location → higher soundness-bug-discovery potential.* D2.H **demonstrates the exploration**; D2.G **adjudicates the bugs**. (Note: D2.G batch-1 triage = **8/0/0 / 0 confirmed candidates so far**, and F26 flags the soundness thesis may be inverted — so an exploration-effectiveness story is the right complementary lens right now.)

---

## 0. Scope & relationship to D2.G

### 0.1 What D2.H IS
The dedicated **constraint-space-exploration notebook + Pro report** for the 4-variant campaign (V5_control / V6_uniform / V6_cTS / Hybrid_cTS). It (a) **reuses** D2.G's already-computed coverage/territory/CGC CSVs (no recompute), (b) adds a set of **exploration-quality + mechanism metrics** D2.G does not produce (per-family reach, marginal contribution, rarity/entropy, proximity-weighted coverage, mode-split discovery, co-failure structure), and (c) packages them as a **narrative .ipynb + .md report with plots** — the artifact to hand Pro, exactly like the D1/V6 notebooks.

### 0.2 What D2.H is NOT
- **NOT the Case verdict / soundness triage** — that's D2.G. D2.H is exploration *effectiveness*, not "did we find a bug" (D2.G owns the triage; D2.H *references* its 0-confirmed result honestly).
- **NOT new campaign data** — analysis only, on the existing DBs + D2.G CSVs. **Low risk** (no production code).
- **NOT a multi-guest / paper claim** — single-guest (sha2-host), directional (Pro D7).

### 0.3 Delta over D2.G (honest)
D2.G already computes coverage AUC + territory exclusive-sets + CGC (for the verdict). D2.H **does not duplicate** that — it imports those CSVs and **adds** the metrics in §3 + the notebook presentation. If a metric already exists in D2.G, D2.H consumes it; the new value is the **exploration-quality/mechanism metrics + the Pro-facing narrative**.

---

## 1. Background

### 1.1 The precedent (reuse-heavy)
`a4/runs/iv_pos_7/analysis/build_v6_pro_notebook.py` is the V6-vs-A4 exploration notebook that fed ProG_Report_3. Its cells map directly: cumulative-coverage curve (Cell 3), loc-overlap/exclusive sets (Cell 5), kind decomposition (Cell 6), CGC apples-to-apples (Cell 8). D2.H **adapts** this to 4 variants + adds §3's metrics. Reusable building blocks: `extract_constraint_family` (`reward_v2.py:65`), `_shannon_entropy` + `_coverage_curve` (`metrics.py:21/33`), `discovery_rate_by_kind_frame` (`discovery_rate.py:36`), `read_normalized_constraint_locs` (`constraint_loc_normalize.py`), and all of D2.G's `d2g_*.csv`.

### 1.2 Inputs (verified available)
- The 4-variant × R=3 × N=10000 campaign DBs (batch-1, seeds 1234/1235, **already collected + analyzed**; batch-2 seed 1236 pending → D2.H runs first on batch-1, then full, mirroring D2.G's phasing).
- D2.G CSVs: `d2g_territory.csv`, `d2g_loc_overlap.csv`, `d2g_apples_to_apples.csv`, `d2g_metrics_table.csv`, `d2g_discovery_rate_by_kind.csv`, `d2g_rejection_channels*.csv`, `d2g_accept_triage*.csv`, the CGC tables.
- Per-DB tables for the new metrics: `failures` (loc + co-failure), `compressed_global_coverage` (CGC), `mutation_rewards` (d_loc/d_glob — fuzzer variants; V6_uniform derives from `failures` per F18), `bandit_decisions` (mode — cTS variants), `mutations` (kind/outcome/index).

---

## 2. Core metrics (Ivan's explicit asks)

| # | Metric | What it shows | Reuse |
|---|---|---|---|
| **C1** | **Cumulative constraint-loc coverage curve** (distinct normalized locs vs applied-pull index; per variant, mean ± seed band) + **local AUC** | The headline "exploration over time" — discovery rate + saturation; AUC = total exploration | `_coverage_curve`, D2.G discovery CSVs |
| **C2** | **Cumulative CGC coverage curve** (distinct CGC contexts vs index) + **CGC AUC** | Global (permutation-argument) constraint-space exploration over time | `cgc_variants` + first-hit indices |
| **C3** | **Final distinct loc / CGC counts** per variant | The endpoint snapshot | D2.G metrics CSV |
| **C4** | **Exclusive sets** — locs + CGCs found by exactly one variant: common / V5-only / V6_uniform-only / V6_cTS-only / Hybrid-only; pairwise Jaccard | **Complementarity** — does each architecture reach territory the others can't? (the central exploration claim) | D2.G `loc_overlap`/`territory` + a CGC analog |

These answer "who explores faster, who saturates, and who reaches unique territory." **C4 is the heart of the exploration story.**

### 2.1 Why local-loc + CGC are the right two coverage curves (Ivan's question)
**Agreed — they are the two best, because they are the two orthogonal structural dimensions of the zkVM constraint space:** local-loc = the *per-row/per-cycle* constraints (the `.zir` EQZ constraints — which specific constraint a mutation makes fail); CGC = the *global, cross-row* arguments (the memory + lookup permutation residues — witness-internal structure). An underconstraint can live in **either**, and the two are **not redundant** (a mutation can move CGC without adding a local loc, and vice versa). So they jointly span the surface. Added a **third, rarity-weighted local curve** (each loc weighted `1/(#variants that ever hit it)` → rewards reaching *rare/exclusive* constraints, not re-hitting common ones — "depth"). Optional finer granularity: `(loc,major,minor)` context count (depth within a constraint) — deferred to v2.

### 2.2 Proportional Venn (Ivan's request) — DECISION
**Two separate area-proportional Venns (local + CGC) — NOT one combined**, because a local-loc and a CGC-context are different units of "space" (merging would be apples+oranges). Caveat (geometric fact): a **true area-proportional Venn is only drawable for ≤3 circles** — so the visual is a **3-set proportional Venn over the surface-distinct variants `{V5(A4), V6_cTS(Arguzz), Hybrid(both)}`** (circle **area ∝ |set|**, region numbers = **exact** counts; geometry illustrative since 3-set area-exact overlap isn't always achievable), and the **complete 4-way decomposition** (all variants, exclusive + common + marginal) is reported as a **table** (a 4-circle proportional Venn is geometrically impossible). `matplotlib_venn` is unavailable (CSP blocks pip) → a **custom proportional-circle drawer** was written.

### 2.3 BUILD STATUS — FINAL, FULL CAMPAIGN (all 12 runs, 2026-06-21)
**Final deliverables:** `a4/runs/iv_pos_8/d2g/d2h_exploration.ipynb` + `.html` (executed, 0 errors, 3 figures) and the standalone **`a4/runs/iv_pos_8/d2g/D2H_REPORT.md`**, both assembled from the analysis library `d2h_lib.py` (now reads all 3 seeds: 1234/1235 from `d2f_prod_b1`, 1236 from `d2f_prod_b2`). The earlier standalone `build_d2h_coverage_venn.py` (3 curves + 2 Venns + 4-way table) remains as the first validated build; its outputs live in `d2h_artifacts/`.

**Notebook cleanup (Ivan review, 2026-06-21).** Ivan read the first HTML and judged the **coverage curves the most insightful**, the **Venns hard to interpret**, and the **UpSet redundant**. After deep review the notebook was reduced to **three figures** that each carry distinct, non-inferrable information, with everything else folded into narrative text:
1. **Coverage curves** (local + CGC) — the headline. Bold line = **both seeds pooled** (endpoint = total distinct reach), faint lines = each seed. Endpoints now **exactly equal** the territory-bar totals (consistency fix: the first build's curves showed per-seed *mean*, which mismatched the pooled set totals).
2. **Territory bars** (local + CGC) — per-variant **total (faded) vs exclusive (solid)**. This single decomposition replaces both proportional Venns *and* the UpSet (it answers "how much is unique?" directly and scales to 4 variants).
3. **Per-family heatmap** — variant × circuit-family local reach (the mechanism/blind-spot view).
**Dropped as redundant/inferrable:** the two proportional Venns, the two UpSet plots, the two composition stacks, the rarity-weighted curve, and the CGC÷local ratio bar (its one insight — Arguzz reaches ~2× more CGC per local loc — is now stated in the discussion text). HTML overlap/cover-up fixed (the culprits were the Venn region labels + UpSet matrix, now removed; family heatmap resized).

**FINAL finding (all 3 seeds):** **A4 (V5/Hybrid) dominates LOCAL coverage (49 locs of a 52-loc union, 34 common to all 4; Arguzz 36–37); Arguzz dominates GLOBAL/CGC (V6_cTS 670 > Hybrid 591 > V6_uniform 565 > V5/A4 449 — A4 reaches the *fewest*).** CGC-per-loc ratio: V6_cTS 18.6 vs V5 9.2 (~2×). Exclusive CGC: V6_cTS 54, V5 46, Hybrid 33, V6_uniform 2; exclusive local: V5 2 (`inst_control:35/36`), V6_uniform 1 (`Poseidon0@inst_p2:470`), others 0 (Hybrid misses all 3 → 49/52, a budget-dilution effect). So the architectures explore **complementary** spaces (A4↔local, Arguzz↔global, Hybrid↔both). **The ProG "A4 reaches global/witness-internal" thesis is INVERTED and confound-proof** — V6_uniform (no bandit) already beats A4 on CGC (565 vs 449), and D2.G's paired test shows V5 −116 CGC vs V6_uniform — directly confirming F26.

---

## 3. New metrics (heavy-thinking additions) — ranked by insight for the hypothesis

The hypothesis is *exploration → underconstraint discovery*. The best exploration metrics measure not just *how much* but *where*, *how deep*, and *how close to a soundness gap*. New, beyond the curves/exclusive-sets:

### HIGH insight
- **N1 — Per-constraint-FAMILY coverage + the kind→family reach matrix.** Group locs by circuit *family* (`extract_constraint_family` → the `.zir` component: `mem`, `inst`/decode, `u32`/arithmetic, `inst_control`, `inst_ecall`, `inst_mem`, `one_hot`, …). Produce (a) a **variant × family coverage heatmap** (which circuit components each architecture probes), (b) a **mutation-kind × family reach matrix** (which kinds reach which families). *Why it's the most insightful:* it shows **WHERE in the circuit** each architecture looks — and therefore the **blind spots** (a family never probed is exactly where an underconstraint could hide undetected) and the **complementarity mechanism** (A4's witness-cell mutations reach families Arguzz's execution-faults don't, and vice versa). This is the mechanistic "why" behind C4's exclusive sets.
- **N2 — Global-vs-local exploration (CGC).** Per variant: **CGC/local coverage ratio** + the **CGC family breakdown** (memory vs lookup permutation families) + CGC exclusive sets. *Why:* A4's witness-internal trace-cell mutations are hypothesized to reach the **global permutation-argument** space (where memory/lookup-argument underconstraints hide) that execution-time faults don't naturally perturb. A variant rich in CGC relative to its local coverage is exploring the *global* constraint space — the A4-vs-Arguzz mechanistic differentiator. (This directly tests the ProG thesis: "A4 adds witness-internal surfaces execution faults don't cover.")
- **N3 — Bug-proximity-weighted coverage.** Per variant: fraction (and exclusive set) of its territory that is **also bug-proximate** — locs with `d_loc≤2` and/or singleton-hit (the D1.C proximity signals). *Why:* this is the **bridge from exploration to the soundness hypothesis** — "high-value territory" near a potential underconstraint. A variant whose coverage is disproportionately bug-proximate is exploring *closer to soundness gaps*, even if it found 0 confirmed bugs. (Reuse the Tier-1 signals already in `l1_signals.py` / `bug_proximity.py`; V6_uniform's `d_loc`/singleton derive from `failures` per F18.)
- **N4 — Marginal coverage contribution (Shapley-style).** For each variant: how much **new** loc/CGC territory it adds to the union of the *other* variants (and the full leave-one-out marginal). *Why:* directly quantifies each architecture's **unique contribution to the combined fuzzer** — the cleanest answer to "what does Hybrid/A4/Arguzz uniquely buy us." More decision-relevant than raw counts.

### MEDIUM–HIGH insight
- **N5 — Mode-split discovery (cTS value).** For V6_cTS/Hybrid: attribute each first-hit loc/CGC to the scheduler **mode that found it** (cold / floor / adaptive, from `bandit_decisions`). *Why:* does the **adaptive** (learned) phase discover territory the floor/cold phases didn't? This is the *direct test of whether cTS's learning adds exploration value* (vs D1.A Finding F's reward-saturation worry) — and it's the mechanism behind any V6_cTS-vs-V6_uniform win.
- **N6 — Exploration breadth/quality:** (a) **Shannon entropy** of the per-loc hit distribution (broad-even vs concentrated), (b) **rarity-weighted coverage** (inverse-frequency weighting — reaching *rare* constraints counts more than re-hitting common ones). *Why:* distinguishes a variant that broadly + deeply probes many constraints from one that hammers a few. Raw count hides this.

### MEDIUM insight
- **N7 — Saturation profile.** Per curve: the **saturation index** (where discovery flattens) + the **post-saturation marginal-discovery slope**. *Why:* a variant still finding new territory at N=10000 has headroom (and N may be too small); connects to D1.A saturation + whether the campaign is long enough.
- **N8 — Co-failure / cascade structure.** Per-loc **co-failure degree distribution** (Suggestion 5): locs hit in *small* cascades / as singletons are cleaner, more diagnostic probes. *Why:* answers Pro's "coverage is less useful if it only appears in giant cascades" — a variant finding more isolated locs explores more *surgically* (each hit is a sharper probe of one constraint).

**Recommended priority for v1:** C1–C4 + N1 + N2 + N3 + N4 (the core curves/exclusive-sets + the four HIGH-insight new metrics). N5–N8 as a second tier if time permits. N1 (family reach) and N4 (marginal contribution) are the two I'd most want in front of Pro.

---

## 4. Notebook + report structure
A `.ipynb` (executable, plots inline) + a `.md` report (the narrative for Pro), structured:

1. **Executive summary** — the headline exploration story: which architecture explores the constraint space most broadly/deeply, the complementarity finding (who reaches unique territory), and what it implies for underconstraint-discovery potential. State up front: this is exploration *effectiveness*, and D2.G's triage found **0 confirmed soundness bugs at N=10000 so far** (honest framing).
2. **§1 Coverage over time** (C1, C2, N7) — local + CGC cumulative curves per variant (mean ± band), AUC, saturation/headroom.
3. **§2 Territory composition** (C3, C4, N4) — the exclusive-set Venn (locs + CGCs), pairwise Jaccard, and the **marginal-contribution** bars (each variant's unique add to the union). The complementarity figure.
4. **§3 Where each architecture looks** (N1) — variant × family coverage heatmap + the kind × family reach matrix + the **blind-spot table** (families no variant / only one variant probes).
5. **§4 Global vs local exploration** (N2) — CGC curves, CGC family breakdown, CGC/local ratio; the witness-internal-reach story (A4's hypothesized strength, tested).
6. **§5 Exploration quality** (N6, N8) — entropy, rarity-weighted coverage, co-failure/cascade distribution.
7. **§6 Bug-proximity-weighted exploration** (N3) — high-value (d_loc≤2 / singleton) territory per variant + its exclusive sets; the bridge to the soundness hypothesis.
8. **§7 Does cTS learning add exploration?** (N5) — mode-split discovery (cold/floor/adaptive); the V6_cTS-vs-V6_uniform mechanism.
9. **§8 Discussion** — what the exploration profiles imply for each architecture's underconstraint-discovery potential; the complementarity verdict (does Hybrid's territory > union pieces?); honest caveats (single-guest; **exploration ≠ confirmed bugs** — 0 so far; the arm-weighting confound — see §7 risk; the F26 thesis-inversion question this data informs).

---

## 5. Files + reuse
| File | Role | Reuse/new |
|---|---|---|
| `a4/runs/iv_pos_8/d2g/exploration_metrics.py` (or `d2h_metrics.py`) | NEW — the §3 metrics (family reach, marginal contribution, rarity/entropy, proximity-weighted, mode-split, co-failure) | new; reuses `extract_constraint_family`, `_shannon_entropy`, `_coverage_curve`, Tier-1 signals |
| `a4/runs/iv_pos_8/d2g/build_d2h_notebook.py` | NEW — assembles the `.ipynb` + plots | model on `build_v6_pro_notebook.py` |
| `IV_POS_8_D2_EXPLORATION_REPORT.md` + `d2h_*.png` + the `.ipynb` | the Pro-facing deliverables | — |
| D2.G `d2g_*.csv` | consumed (not recomputed) | reuse |
**Danger:** LOW — analysis-only, no production/scheduler/binary changes, consumes existing DBs + CSVs (like D2.G). The only correctness care: the **same arm-weighting confound** that affects D2.G (V6_cTS over-samples high-arm-count kinds) also colors raw coverage — so coverage/territory comparisons must be reported **per-kind / per-family-normalized**, not just pooled (carry D2.G's normalization).

---

## 6. Sequencing
- **Depends on D2.G** (its CSVs + the validated DBs). Build the §3 metric module + notebook **now** (campaign-independent code), validate on **batch-1** (seeds 1234/1235, available), then run on the **full** campaign when batch-2 (seed 1236) lands — mirroring D2.G's smoke→first-N→full ladder.
- **Phased validation:** (a) the metric functions on batch-1 DBs (shapes, V6_uniform F18 handling, no crashes); (b) the notebook renders end-to-end; (c) full run + the Pro report on the complete 4×3 set.
- **Feeds:** the Pro check-in (the exploration story alongside D2.G's verdict) + Phase-5 decisions (the complementarity/blind-spot findings inform "which architecture / which next guest").

---

## 7. Risks / flags
| # | Risk | Severity | Mitigation |
|---|---|---|---|
| **DH-1 — exploration ≠ bugs** | A compelling exploration story could be over-read as "found bugs." | Med | §0/§8 state explicitly: D2.G triage = 0 confirmed; exploration is *potential*, the hypothesis, not a result. |
| **DH-2 — arm-weighting confound in coverage** | V6_cTS over-samples high-arm-count kinds (INSTR_WORD_MOD) → its coverage profile is sampling-shaped, not capability-shaped. | Med | Report per-kind/per-family-normalized coverage (N1); flag any exclusive-territory that's an over-sampling artifact (carry D2.G's normalization). |
| **DH-3 — V6_uniform sparse telemetry (F18)** | No `mutation_rewards`/`bandit_decisions` → N3 (d_loc/singleton) must derive from `failures`; N5 (mode-split) is N/A for V6_uniform. | Low | F18-safe derivations; mark cTS-only metrics N/A for V6_uniform. |
| **DH-4 — overlap with D2.G** | Recomputing what D2.G already has wastes effort + risks divergent numbers. | Low | Consume D2.G CSVs; D2.H only *adds* §3 metrics + presentation. |
| **DH-5 — single-guest** | Exploration profiles are sha2-host-specific (esp. family coverage — some families only exist on paging/BigInt guests). | Low | Caveat in §8; the blind-spot analysis explicitly notes guest-dependence (ties to IV.POS.9 multi-guest). |

---

## 8. Open questions for Ivan
1. **Metric priority:** confirm the v1 set (C1–C4 + N1–N4) — especially that **N1 (per-family reach matrix)** and **N4 (marginal contribution)** are worth the build. Any of N5–N8 you specifically want in v1?
2. **Any metric I'm still missing** that you'd find insightful for "exploration → underconstraints"? (Candidates I considered but didn't prioritize: a reachability-ceiling estimate; a per-loc first-finder leaderboard; coverage-velocity-decay.) 
3. **D2.H vs folding into D2.G's report:** keep it a separate exploration notebook (the D1/V6 precedent), or merge into the D2.G Pro report? I recommend **separate** (it's a distinct narrative + audience-friendly artifact), reusing D2.G's data.
4. **Timing:** build now + validate on batch-1, or wait for the full 4×3? I recommend **build now, validate on batch-1** (catches issues early; the curves are already meaningful at 2 seeds).

---

## 9. Changelog
| Date | Author | Version | Notes |
|---|---|---|---|
| 2026-06-21 | Opus-CP (acting D2-Opus) | v0.1 PRELIMINARY | Constraint-space-exploration notebook + report for the 4-variant campaign, post-D2.G. Reuses `build_v6_pro_notebook` precedent + D2.G CSVs; core = coverage curves + exclusive loc/CGC sets (Ivan's asks); new = per-family reach matrix (N1), CGC global-vs-local (N2), bug-proximity-weighted coverage (N3), marginal contribution (N4), mode-split discovery (N5), entropy/rarity (N6), saturation (N7), co-failure (N8). Notebook + report structure §4. Low risk (analysis-only). Awaiting Ivan review of the metric set (§8). Context: D2.G batch-1 triage = 0 confirmed candidates / 8-0-0; F26 flags possible thesis inversion → exploration lens is timely. |
| 2026-06-21 | D2-Opus | v1.0 FINAL | **Full campaign complete (all 12 runs: 4 variants × 3 seeds × N=10000).** Notebook (`d2h_exploration.ipynb`/`.html`) rebuilt on the complete 3-seed data via `build_d2h_notebook.py` + `d2h_lib.py` (seeds 1234/1235 in `d2f_prod_b1`, 1236 in `d2f_prod_b2`); cleaned to 3 figures (coverage curves, total-vs-exclusive territory bars, per-family heatmap), curve endpoints reconciled to pooled-union totals, all provisional hedging removed. **Standalone report written: `a4/runs/iv_pos_8/d2g/D2H_REPORT.md`.** Final numbers: LOCAL union 52 / common-4 34 (V5=Hybrid=49, Arguzz 36–37); CGC V6_cTS 670 > Hybrid 591 > V6_uniform 565 > V5 449; CGC/loc ratio V6_cTS 18.6 vs V5 9.2 (~2×). **F26 thesis inversion CONFIRMED and confound-proof** — V6_uniform (no bandit) reaches 565 CGC vs A4's 449; D2.G paired test = V5 −116 CGC vs V6_uniform. **Case B** per D2.G's normalized-territory gate (V6_cTS only ties V6_uniform on local locs; its CGC lead is non-gating + arm-weighting-confounded, so feedback does not beat round-robin on the gate). Triage = 0 confirmed candidates. |
