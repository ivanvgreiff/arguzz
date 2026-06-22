# D2.H — Constraint-Space Exploration Report (IV.POS.8 full campaign)

**Author:** D2-Opus · **Date:** 2026-06-21 · **Status:** FINAL (all 3 seeds, 12 runs complete)
**Companion artifacts:** `a4/runs/iv_pos_8/d2g/d2h_exploration.ipynb` (+ `.html`), built from `d2h_lib.py`.
**Scope:** how broadly and deeply each fuzzing architecture explores the RISC Zero zkVM constraint system. This is the *coverage* counterpart to D2.G's *verdict/triage* analysis.

---

## 0. TL;DR (read this if nothing else)

Across the complete campaign (4 architectures × 3 seeds × N=10000 mutations), the headline is **complementarity along a local-vs-global axis**, and it **inverts the framing we carried into ProG**:

| Finding | Evidence | So what |
|---|---|---|
| **A4 owns the *local* constraint surface** | V5/Hybrid reach **49** of 52 distinct per-row locs; pure-Arguzz reaches **36–37** | A4's post-execution cell mutations broadly trip per-row `EQZ` constraints |
| **Arguzz owns the *global* (CGC) surface — A4 reaches the *fewest*** | V6_cTS **670** CGC vs V5/A4 **449**; even feedback-free V6_uniform (565) beats A4 | **Inverts the prior "A4 reaches global/witness-internal" thesis** (flag F26) |
| **Measured per local loc, Arguzz reaches ~2× more global structure** | CGC/loc ratio: V6_cTS **18.6** vs V5 **9.2** | The architectures are genuinely orthogonal, not redundant |
| **Hybrid is the only variant strong on *both*** | 49 local **+** 591 CGC (2nd-highest) | Supports the Hybrid hypothesis on coverage grounds |
| **The local surface is shared; the global surface is differentiated** | 34 of 52 local locs common to all 4; CGC exclusive: V6_cTS 54, V5 46, Hybrid 33, V6_uniform 2 | If you must pick one knob to differentiate architectures, it's global reach |

**Crucial caveat:** this is about *coverage of the search space*. D2.G triage found **0 confirmed soundness candidates** in the entire campaign. "Reaches more territory" = "more chances to find a bug," **not** "found one."

---

## 1. Background — what was run and why (self-contained)

### 1.1 The two architectures being compared
We are fuzzing the RISC Zero zkVM to hunt for **soundness bugs** — places where the proof circuit would *accept* a witness/trace it should *reject* (an **underconstraint**). Two mutation architectures generate the candidate-faulty executions:

- **A4** — *post-execution* mutation. The guest program runs to completion, then A4 perturbs a **single witness/trace cell** (the recorded execution data the prover commits to) and asks the verifier whether it still accepts. 11 live mutation kinds on this guest.
- **Arguzz** — *during-execution* fault injection. Arguzz injects a fault **while the VM is executing** (e.g. corrupting a register/memory value mid-step), then proving proceeds over the faulted execution. Also 11 kinds.

A soundness bug found by either is equally valid; the open question is **which architecture exercises more of the circuit**, and whether combining them helps.

### 1.2 The four variants (each N=10000, sha2-host, seeds 1234/1235/1236)
| variant | mutation surface | scheduler | role |
|---|---|---|---|
| **V5_control** | A4 (11 kinds) | cTS, constant floor | pure-A4 baseline |
| **V6_uniform** | Arguzz (11 kinds) | round-robin (uniform) | pure-Arguzz, no feedback |
| **V6_cTS** | Arguzz (11 kinds) | constrained Thompson sampling | pure-Arguzz, with feedback |
| **Hybrid_cTS** | A4 + Arguzz (15 kinds) | constrained Thompson sampling | the combined architecture |

cTS = a bandit that **learns** which mutation kinds are productive and samples them more (with a floor so nothing starves). V6_uniform is the no-feedback control for isolating the value of that learning.

### 1.3 What "constraint-space coverage" means — the two dimensions
A zkVM constraint system has **two structurally different kinds of constraint**, and an underconstraint can live in either. We therefore measure two coverage curves:

- **Local coverage** (`coverage` table, keyed by `constraint_loc`): the **per-row / per-cycle** algebraic constraints — the `.zir` `EQZ` equalities. A local-loc is **reached** when some mutation makes *that specific constraint* fail. *Intuition: which individual constraints did the fuzzer manage to trip?*
- **CGC coverage** (`compressed_global_coverage` table, keyed by `ctx_key`): **global, cross-row** arguments — the memory + lookup **permutation** residues that bind the entire trace together. *Intuition: which global, witness-internal structures did the fuzzer manage to perturb?*

These are **orthogonal**: a mutation can move a CGC residue without adding any local loc, and vice versa. Together they span the surface a soundness bug could occupy. (A rarity-weighted curve was prototyped and dropped — it is a re-weighting of the local axis, not a new dimension, and added no insight the two primary curves don't.)

### 1.4 Method notes
- **All numbers are computed live** from the 12 run DBs by `d2h_lib.py` — nothing in the notebook or this report is hardcoded.
- **Pooling:** the bold coverage curve pools all 3 seeds (a constraint counts once it is reached in *any* seed); its endpoint therefore equals the campaign's **total distinct reach** and matches the territory bars exactly. Faint per-seed lines show run-to-run reproducibility.
- **"Exclusive"** territory = locs/CGC contexts reached by exactly one variant (pooled over its 3 seeds), i.e. its unique contribution that no other architecture would have found.

---

## 2. Findings in detail

### F1 — Local coverage: A4 leads, the surface is near-saturated and largely shared
**Numbers (distinct local locs, pooled over 3 seeds):** V5_control **49**, Hybrid_cTS **49**, V6_uniform **37**, V6_cTS **36**. Union across all four = **52**; **34** are reached by *all four*.

The two A4-containing variants reach the most local constraints; the pure-Arguzz variants reach ~25% fewer. The local curve **saturates by ~2–3k pulls** — the ~50 reachable local locs on this guest are nearly exhausted early, and the rest of the campaign adds little local territory. The surface is also **highly shared**: two-thirds of the union is common to every variant.

**Why A4 leads locally:** a single post-execution cell edit directly violates the per-row equality that reads that cell, so A4 reliably trips local `EQZ` constraints. A during-execution fault changes downstream *values*, which more often shifts global residues than cleanly violating a specific local equality.

### F2 — CGC coverage: Arguzz leads, and **A4 reaches the *fewest*** (the thesis inversion)
**Numbers (distinct CGC contexts, pooled over 3 seeds):** V6_cTS **670**, Hybrid_cTS **591**, V6_uniform **565**, V5_control **449**.

This is the most important result. The pre-campaign framing (carried into ProG) was that *A4's* witness-internal mutations are what reach the *global* witness structures. **The data says the opposite.** Normalized as **CGC contexts reached per local loc**:

| variant | CGC | local | CGC/loc |
|---|---:|---:|---:|
| V6_cTS | 670 | 36 | **18.6** |
| V6_uniform | 565 | 37 | 15.3 |
| Hybrid_cTS | 591 | 49 | 12.1 |
| V5_control (A4) | 449 | 49 | **9.2** |

Arguzz reaches **~2× more global structure per local loc** than A4. **It is Arguzz, not A4, that is the global-reaching architecture**; A4 is the broad *local* explorer.

**This is robust to the bandit confound.** One might worry V6_cTS's lead is an artifact of its bandit over-sampling the high-arm-count `INSTR_WORD_MOD` kind (its share climbs 0.29→0.35 over the run). But the clean control settles it: **V6_uniform — round-robin, no arm-weighting at all — still reaches 565 CGC vs A4's 449.** D2.G's paired test states it directly: **V5_control is −116 CGC vs V6_uniform** (and V6_cTS is +131). The inversion is real, not a sampling artifact. *(This is the empirical basis for flag F26.)*

### F3 — Exclusive territory: local is shared, global is differentiated; Hybrid is a unifier
**Exclusive local locs:** V5 **2** (`ControlLoadRootAndNonce@inst_control.zir:35` and `:36`), V6_uniform **1** (`Poseidon0@inst_p2.zir:470`), V6_cTS **0**, Hybrid **0**.
**Exclusive CGC contexts:** V6_cTS **54**, V5 **46**, Hybrid **33**, V6_uniform **2**.

Two readings:
- **Local territory is near-interchangeable.** Exclusive local counts are tiny — all four variants reach essentially the same shared core, and differences are at the margins. Notably **even Hybrid misses all 3 exclusive local locs** (so Hybrid = 49/52). A plausible mechanism: splitting the bandit budget across 15 kinds instead of 11 slightly *dilutes* A4's per-kind sampling, so Hybrid doesn't always trip the rarest A4-only local constraints that pure-A4 V5 does. (The per-family heatmap confirms this exactly: V5 reaches **10** `inst_control` locs to Hybrid's **8** — a 2-loc gap that is precisely those two exclusive locs.)
- **Global territory is genuinely differentiated.** Exclusivity here is large. V6_cTS contributes the most brand-new global contexts (54). Interestingly, **Hybrid's *exclusive* CGC (33) is lower than both V6_cTS and V5** — not because it reaches less (it reaches 591, second-most overall) but because most of its territory **overlaps its two parents**. Hybrid is a **broad unifier of A4 + Arguzz regions, not a generator of new ones.**

### F4 — Per-family reach: where they diverge, and blind spots
Grouping local locs by circuit family (`.zir` component):
- **Shared core** (covered near-identically by all four): `inst`, `mem`, `u32`, `one_hot`, `inst_sha`, `inst_ecall`.
- **Where A4 pulls ahead:** the decode/control families — `inst_control` (V5 10 / Hybrid 8 / Arguzz 6), `inst_div` (A4 1 / Arguzz 0), `inst_mul` (A4 2 / Arguzz 0), `inst_misc` (A4 1 / Arguzz 0). This is the mechanistic source of A4's local lead.
- **Thinnest coverage (blind-spot candidates):** `inst_p2` (Poseidon, 1–2 locs) and `inst_div`. No family is fully empty on this guest, but these are the natural targets for a future guest or a new mutation kind — where an underconstraint would be least likely to be tripped today.

### F5 — Secondary signals (from D2.G, for context)
- **Global (CGC) reach: V6_cTS > V6_uniform (670 vs 565) across all 3 seeds — but this is *not* the Case verdict.** D2.G's authoritative Case gate is normalized *local* territory, on which V6_cTS only **ties** V6_uniform (36.0 vs 35.0 mean; +1, within seed noise) → **Case B**: feedback does *not* beat round-robin on the gating metric. The CGC lead is non-gating and confounded by `INSTR_WORD_MOD` over-sampling (caveat 2), and the bug-proximal comparison is undermined by V6_uniform's telemetry artifact (see the bug-proximity item below). So the cTS-vs-uniform CGC ordering is an exploration-breadth observation, not a validated "learning beats round-robin" result.
- **Allocation entropy:** Hybrid has the highest per-kind allocation entropy (~3.65 — it spreads across 15 kinds), V6_cTS the lowest (~3.03 — the bandit concentrates). This is the quantitative form of the "dilution" mechanism in F3.
- **Bug-proximity (`d_loc≤2`), reported with a caveat:** the feedback/A4 variants register many *unique* bug-proximal locs (Hybrid 40, V6_cTS 36, V5 31); V6_uniform shows 0 **but that is a telemetry artifact** — V6_uniform's `local_coverage_v2` table is empty (`telemetry_sparse=True`), so the derived unique-useful metric can't be credited for it. Its raw `d_loc≤2` failure *rate* is in fact ~0.53, comparable to the others. **Do not read V6_uniform's 0 as "feedback-free finds nothing."** We rely on the clean coverage metrics (F1–F3), not this one.

---

## 3. Synthesis — what the campaign tells us

1. **The architectures are complementary, not redundant.** A4 ↔ local, Arguzz ↔ global, Hybrid ↔ both. The axis is local-vs-global, and the pre-campaign labels were backwards (F2). Running A4 *and* Arguzz covers strictly more of the constraint space than either alone — the correct hedge when hunting for an unknown underconstraint.
2. **The Hybrid hypothesis is supported on coverage grounds.** Hybrid matches A4's local breadth (49/52) and inherits most of Arguzz's global reach (591, 2nd-highest CGC). Its one cost is mild: the 15-way budget split slightly dilutes A4's local *depth* (it misses the 3 rarest exclusive local locs), and its exclusive CGC is modest because it re-covers its parents rather than opening new regions.
3. **Feedback (cTS) does not beat round-robin on the Case gate (Case B).** On D2.G's authoritative metric — normalized *local* territory — V6_cTS ties V6_uniform (36.0 vs 35.0 mean) and reaches slightly *fewer* pooled local locs (36 vs 37). V6_cTS does reach more *global* (CGC) territory (670 vs 565), but that axis is non-gating and confounded by `INSTR_WORD_MOD` over-sampling, so it is exploration breadth, not evidence that learning beats round-robin. The bandit's concentration is visible (lower entropy, IWM escalation).
4. **What to run next.** On coverage logic, the productive configuration is Hybrid (broadest single explorer) complemented by a pure-A4 arm to retain the rare local depth Hybrid dilutes. The thinnest families (`inst_p2`, `inst_div`) and a second guest (IV.POS.9, which may activate the currently-dead A4 paging/cycle kinds) are the highest-value coverage expansions.

---

## 4. Caveats (don't over-read)
1. **Exploration ≠ bugs.** 0 confirmed soundness candidates campaign-wide. Everything here is *potential*, not realized, bug-finding.
2. **Sampling confound on absolute CGC magnitudes.** V6_cTS's bandit over-samples `INSTR_WORD_MOD`, inflating its raw CGC count somewhat. The *direction* of F2 is confound-proof (V6_uniform, no bandit, still beats A4), but treat exact CGC magnitudes as upper-ish.
3. **Single guest.** All runs are sha2-host. Guest-specific families (`inst_p2` Poseidon, BigInt) would change the family picture elsewhere, and currently-dead A4 paging/cycle kinds may activate on a Poseidon-paging guest. The local-vs-global complementarity is expected to hold; absolute family coverage is guest-specific.
4. **Small-n statistics.** Paired tests over 3 seeds have huge effect sizes but undefined p-values (`small_n_caveat=True` throughout). The seed-to-seed spread (faint curves) is small, so the rankings are stable, but we report effect sizes, not significance.

---

## 5. Appendix

### 5.1 Exact coverage table (pooled over 3 seeds)
| variant | local total | local exclusive | CGC total | CGC exclusive | CGC/loc |
|---|---:|---:|---:|---:|---:|
| V5_control | 49 | 2 | 449 | 46 | 9.2 |
| V6_uniform | 37 | 1 | 565 | 2 | 15.3 |
| V6_cTS | 36 | 0 | 670 | 54 | 18.6 |
| Hybrid_cTS | 49 | 0 | 591 | 33 | 12.1 |
| **union / common-4** | **52 / 34** | — | **1025 / 110** | — | — |

### 5.2 Runtime (measured from each run's `campaigns.started_at/ended_at`)
Per N=10000 job: **5.5–9.2 h** (Arguzz variants 5.5–6.5 h; A4-containing variants 7.3–9.2 h — A4's extra trace-mutation work). Full 12-job campaign ≈ **84 machine-hours** sequential, on an 8-core x86-64 host (~5 cores/proof, ~0.3 GB RAM/proof, CPU-only).

### 5.3 Reproduce
```bash
cd /root/arguzz
python3 a4/runs/iv_pos_8/d2g/build_d2h_notebook.py   # rebuilds .ipynb + .html (0 errors, 3 figures)
```
Data: `a4/runs/iv_pos_8/d2f/prod/d2f_prod_b1` (seeds 1234/1235) + `…/d2f_prod_b2` (seed 1236). Library: `d2h_lib.py`. Spec: `a4/docs/cloud2/IV_POS_8_D2_H_SPEC.md`.
