# IV.POS.8 — Pro Check-in (post-implementation, pre-integration)

**To:** ChatGPT Pro · **From:** Ivan (+ Cursor-Opus/Composer pairs) · **Date:** 2026-06-19
**Prior context you (Pro) wrote:** `ProG_Report_3.md` (your last guidance — this doc uses your nomenclature where possible).

---

## 0. What this is and what I need from you

Since `ProG_Report_3`, I built out two work-streams as **deliberately separate components**, and I'm now at the point where the next two phases (**D1.E** and **D2.C**) *integrate* them. Before I commit weeks to that integration, I need your architecture call on **what to integrate, what to drop, and what new thing to try** — based on everything implemented and all results so far.

- **D1** = housekeeping + scheduler/reward tuning (your Priority 4 + the §5/§7/§11 asks).
- **D2** = Hybrid V7 construction (your Priority 1 + 3): the foundation + the pure-A4 catalog expansion.
- **D1.E** and **D2.C** are the *integration* phases (reward-engine integration; A4+Arguzz surface integration). **They are specs only — not yet built.** That's deliberate: I want your steer first.

**You have no access to my repo** — §1 below is a self-contained definitions/nomenclature primer (with source snippets) so every later claim is grounded. §2 is per-phase findings. §3 is cross-cutting findings. §4 is the integration plan. **§5 is the explicit set of decisions I need from you.** §6 indexes the deeper artifacts I'm attaching.

### 0.1 Scope & caveats (read before the findings)
- **One guest.** All campaigns run on a single guest program (**`sha2-host`**, a ~3930-step trace). Multi-guest (your §13) is future work. **This bounds every finding** — most importantly, the D2.B "dead arm" classifications are scoped to this guest's **user-instruction cycles** (e.g. one dead kind is plausibly *live* on paging cycles), and the decay/singleton dynamics could differ on other workloads.
- **Decay sample is n=5 paired triplets** (a POS infrastructure failure truncated the planned n=10). Directional, not high-powered.
- **D1.A/B/C are post-hoc analysis on frozen campaign DBs** — they identify *candidates* and characterize properties; they do **not** prove the bandit benefits from learning on them (that's D1.E's forward-run job).
- **No Hybrid-cTS results exist yet** — Hybrid isn't built. For the integration phases (§4) you are reacting to *plans*, not results. That's the point of this check-in: steer before I build.

---

## 1. Definitions & nomenclature (self-contained — Pro has no repo access)

### 1.1 The two fuzzing surfaces
- **A4** (my framework) = **post-execution trace mutation.** The guest runs once; the RISC Zero prover records a *preflight trace* (per-cycle records + memory-transaction records); A4 then mutates a single field of that trace *in Rust, after execution but before witness generation*, and observes whether a constraint rejects. Surgical, single-cell, attacks the witness/prover layer directly.
- **Arguzz** = the prior paper's approach (arXiv 2509.10819) = **during-execution fault injection.** It perturbs a register/memory/PC/branch *during* the guest's execution and lets the VM propagate the consequences through subsequent cycles. In my variant naming, **Arguzz ≡ V6-uniform**.

### 1.2 The variants (scheduler × kind-set × surface)
| Variant | Scheduler | Kinds | Surface | Role |
|---|---|---|---|---|
| **V1** | kind-only constrained-TS | 8 A4 | A4 trace-cell | prior-round baseline |
| **V5** | constrained-TS over `(kind, semantic_zone)`, floor-dominated | 8 A4 (now 11) | A4 trace-cell | the architectural win you validated; the Mode-A survey engine |
| **V6-uniform** (=Arguzz) | balanced round-robin | **11 Arguzz** | exec-fault | faithful Arguzz baseline |
| **V6-cTS** | constrained-TS | **11 Arguzz** (same set as V6-uniform) | exec-fault | "does my feedback loop improve Arguzz?" — **scheduler-only ablation, so it must hold the kind set constant** |
| **Hybrid-cTS** (=Hybrid V7) | constrained-TS, one shared arm space | 11 A4 + **4 selected** Arguzz | both | the candidate winning endpoint you prioritized; the 4 = Pro §8 Track A top-4 (see design note) |

> **Design note (D2.C v0.4-aligned):** **V6-cTS uses all 11 Arguzz `ENABLED_KINDS`** — the same set V6-uniform runs — so the V6-uniform-vs-V6-cTS comparison isolates the *scheduler* alone (round-robin vs cTS), not a kind-set change. **Hybrid-cTS** imports a curated **4**: Pro §8 Track A items 1–4 (`INSTR_WORD_MOD`, `PRE_EXEC_MEM_MOD`, `PRE_EXEC_PC_MOD`, `BR_NEG_COND`); items 5–7 (`POST_EXEC_REG/MEM/PC_MOD`) are deferred. Four *other* Arguzz kinds (`COMP_OUT_MOD`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`, `PRE_EXEC_REG_MOD`) are excluded *from Hybrid* because they **name-duplicate** existing A4 `MUTATION_KINDS` (avoiding redundant arms in Hybrid's shared space) — a separate constraint from Pro's priority order. The Arguzz binary supports all 11 (no new Rust work); D2.C v0.4 splits the kind-list into `MUTATION_KINDS_ARGUZZ_FULL` (11, V6-cTS) and `MUTATION_KINDS_ARGUZZ_SELECTED` (4, Hybrid-cTS).

(V2–V4 were diagnostic variants from the prior round; not in play.)

### 1.3 Proving pipeline & key terms
- **Preflight trace** → **witness** → **constraints**. The prover runs the guest (execution), records the **preflight trace** (cycle records + memory transactions), then **witgen** reads the trace through C++ **externs** to populate the **witness** (polynomial column tables); **constraints** are polynomial equations over witness columns that must hold for the proof to verify.
- **extern** = a C++ function the generated witgen code calls to pull values from the preflight trace (e.g. `extern_getMemoryTxn`). *A mutation only matters if the field it touches is actually returned by an extern and reaches the witness* — this is the crux of the dead-arm finding (§2.5).
- **CGC (Compressed Global Context)** = a bucketed key for *global* (cross-row) constraint residues — the memory-permutation and lookup arguments. Used as a discovery/reward signal distinct from local constraint locations.
- **Soundness bug** = `invalid semantic execution + proof ACCEPTED`. **Completeness/overconstraint bug** = `valid execution + proof REJECTED`.

### 1.4 The reward & scheduler (source-grounded)
The bandit's per-pull success bit (what Thompson sampling learns from) is a **sparse binary composite** — one bit per pull, true iff the mutation discovered anything new across local / compressed-global / structural channels:
```python
# reward_v2.py
def compute_bandit_success(l_new, g_new, s_new) -> int:
    return 1 if (l_new + g_new + s_new) > 0 else 0
```
**Note: acceptance is NOT in the reward — the reward is coverage-based.** (This matters for the §5 accept-signal decision.)

The bandit **arm** identity (post-foundation work) is a 5-tuple:
```python
# semantic_arm_universe.py
@dataclass(frozen=True, order=True)
class ArmKey:
    surface: str       # "A4_trace_cell" | "arguzz_exec_fault"
    kind: str          # mutation kind
    zone: str          # semantic zone of the target cycle
    opcode_class: str  # arithmetic/memory_load/.../"n/a"
    pre_post: str      # "pre_exec"/"post_exec"/"n/a"
```
A4 arms collapse the last two fields to `"n/a"` (V5 back-compat); Arguzz arms use all five.

The scheduler is **floor-dominated**: a `coverage_floor_fraction` (default 0.55) forces broad "floor" exploration; an adaptive Thompson-sampling tail exploits. The floor share is set by a `FloorSchedule` (`ConstantFloor` / `ExponentialDecayFloor` / `EpochStageFloor`). **Per-pull outcome accounting** uses `MutationOutcome ∈ {APPLIED, SKIPPED, ERROR}`, with an optional `applied_accounting_mode` so only APPLIED mutations count as bandit pulls (your §8 ask — Arguzz no-ops shouldn't count as pulls).

The live A4 mutation registry is 11 kinds:
```python
# fuzzer.py  (8 original V5 + 3 D2.B-live)
MUTATION_KINDS = [COMP_OUT_MOD, LOAD_VAL_MOD, STORE_OUT_MOD, PRE_EXEC_REG_MOD,
                  INSTR_TYPE_MOD, MEM_VAL_MOD, INSTR_WORD_MOD_FULL, INSTR_WORD_MOD_SUR,
                  TXN_PREV_WORD_MOD, TXN_PREV_CYCLE_MOD, CYCLE_DIFF_COUNT_MOD]
```
D2.C imports the Arguzz exec-fault kinds in **two scope tiers** (per the §1.2 design note): **all 11 `ENABLED_KINDS` for V6-cTS**, and **the 4 high-yield kinds** `INSTR_WORD_MOD`, `PRE_EXEC_MEM_MOD`, `PRE_EXEC_PC_MOD`, `BR_NEG_COND` (Pro **§8 Track A top-4**, lines 228–238) **for Hybrid-cTS**.

### 1.5 Bug taxonomy & rejection channels
- **Live arm** = a mutation kind whose mutated value actually reaches the witness and can trigger a constraint. **Dead arm** = the mutation is applied to the trace but the field never enters the witness (structurally inert; the proof still attests the original, correct execution — **not** a soundness bug).
- **W-17 / W-18** = the two dead-arm mechanisms (§2.5).
- **4-channel rejection model** — a mutation can be "caught" four ways: **C1** local `<constraint_fail>` tag; **C2** `verify segment` prover panic (global polynomial / memory-permutation imbalance, *no local tag*); **C3** Hook-3 per-family residue (opt-in); **C4** dispatcher error. (Arguzz adds **C5** = guest panic during prover startup, before it finalizes — `prover_status="start"` + host panic.) *Different mutations reject through different channels* — e.g. one A4 sub-strategy rejects via C1 (local tag), its sibling via C2 (panic, no tag).
- **Soundness-bug guard** fires when: mutation applied + trace demonstrably changed + *no* rejection channel fired + verifier accepted. This is the detector for accepted-invalids — but it also fires on fault-no-ops (the confound; see §3.1).
- **FIE** (`FAULT_INJECTION_ENABLED`) = an existing RISC Zero flag that suppresses C++ sanity-check `throw`s so a mutation can proceed to the constraints instead of crashing; it does *not* change witness binding or constraint logic.

### 1.6 Metric stack
- **`local_context_final`** = distinct local constraint locations discovered in a campaign (saturates ~46 for V5). **`d_loc`/`d_glob`** = per-pull count of distinct local/global failure contexts. **`singleton_failure_rate`** = fraction of pulls breaking exactly one failure. **CGC count** = distinct compressed-global keys discovered.
- **Reward-rewire layers (my shorthand):** **L0** = the CGC bucketing scheme feeding `g_new`. **L1** = OR-ing extra per-mutation signals into `bandit_success`. **L2** = replacing the binary Bernoulli reward with a scalar-reward bandit (deferred).

### 1.7 Deliverable map (→ your §15 priorities)
| Mine | Theme | Your priority | Status |
|---|---|---|---|
| D1.A | V5 decaying-floor variant | Priority 4 / §7 | done (frozen) |
| D1.B | CGC coarsening variants | §11 | done |
| D1.C | bug-proximity metric stack | §5 | done |
| D2.A | Hybrid-V7 foundation (5-tuple arm, outcome, normalization) | enabler for §1/§15 | done |
| D2.B | pure-A4 kind expansion | Priority 3 / §8 | done |
| **D1.E** | reward-rewire re-run (integration) | §7 Stage-2 | **spec only** |
| **D2.C** | Arguzz integration (integration) | Priority 1 (toward §9 variants) | **spec only** |
| D2.D–G | variant CLI / tests / dispatch / cross-variant analysis | Priority 1 | spec'd, not started |

### 1.8 The actual semantic mappings (for the §5 Q8 soundness review)
These are the predefined mappings I'm asking you to sanity-check. All are derived from RISC Zero's real circuit/VM structure, not invented.

**Semantic zones (19)** — derived from the circuit's cycle `major`/`minor`:
- *Boundary (8):* `step0`, `last_step`, `pre_ecall`, `post_ecall`, `pre_mret`, `post_mret`, `pre_halt`, `post_halt`.
- *Core (11):* `core_arithmetic`, `core_memory_load`, `core_memory_store`, `core_branch`, `core_mul`, `core_div`, `core_shr`, `core_sha`, `core_poseidon`, `core_other`, `kernel_other`.
- **On the current guest (sha2-host), several are empty/rare** — `core_sha`, `core_poseidon`, `pre_mret`/`post_mret`, `pre_halt`/`post_halt` — which is part of why a second guest matters (Q7).
- `major→zone`: 0–2→arithmetic, 3→mul, 4→div(/shr), 5→memory_load, 6→memory_store, 7→branch, 9–10→poseidon, 11→sha, else→other.

**Two opcode_class taxonomies (intentionally different granularity):**
- *Arm-identity `opcode_class` (7):* `arithmetic`, `memory_load`, `memory_store`, `branch`, `jump`, `ecall_mret`, `system` — bandit-arm identity (so the scheduler can learn per-opcode-class; load/store are split because they're distinct arms).
- *CGC/telemetry `opcode_class` (8):* `alu`, `mul`, `div`, `mem`, `branch_or_ctrl`, `poseidon`, `sha`, `other` — used for global-context compression (load/store lumped as `mem`).

**`pre_post` (the 5th ArmKey field)** — `pre_exec` vs `post_exec`. A4 arms collapse it to `n/a`; the Arguzz kinds populate both sides (5 `pre_exec`: PRE_EXEC_*/INSTR_WORD_MOD/BR_NEG_COND; 6 `post_exec`: POST_EXEC_*/COMP_OUT_MOD/LOAD_VAL_MOD/STORE_OUT_MOD). **D2.C/V6-cTS is the first time D2.A's `pre_post` axis is exercised on both sides** (it was effectively `pre_exec`-only before).

**`txn_role` (6)** — the memory-transaction role attributed to a CGC memory context: `read`, `write`, `ifetch`, `register`, `prev_word`, `prev_cycle`.

**CGC memory key** = `(family, address_region, address_bucket, txn_role, cycle_phase)`, where `address_region` ∈ 9 D8 VM bands (user / user_regs / kernel / machine_regs / …) and `address_bucket = floor(log2(byte_addr))`. My `page_class` (Q2) is an *additional* ELF-derived semantic carve of the **D8 `user` band `[0x10000, 0xBFFF0000)`** — all 7 sub-classes (`stack`/`text`/`rodata`/`data_bss`/`heap`/`host_ecall`/`user_dynamic`) lie *within* it (`host_ecall` is the HOST_ECALL MMIO buffer at `0x42000000`, inside the user band — not the D8 `ecall_dispatch` region, which is at `0xFFFF1000`).

*My validation method:* source-level mechanism reasoning (does each category correspond to a real distinction in how the circuit treats it), not empirical trace-by-trace sweeps — see Q8.

---

## 2. What was implemented + headline findings (per phase)

### 2.1 D1.A — V5 decaying-floor variant *(your §7)*
**Did:** built three floor schedules (static 0.55 / exponential-decay / epoch-staircase) and compared V5-static vs V5-decay on paired seeds, N=6000.
**Found:**
- **Decay does not move the headline metric** (`local_context_final` 46.4 / 46.2 / 46.4; paired p > 0.62). The *interesting* part is the mechanism:
- **The key empirical result (adaptive vs floor):** the exponential-decay variant gave the **adaptive bandit ~13× more decision share** (≈52% of post-cold-start pulls vs V5-static's ≈4%, because K=50 collapsed the floor to its minimum almost immediately). Result: **the discovery ceiling did not move** (`local_context_final` 46.2 vs 46.4, p=0.70; compressed-global tied). At most there was a *non-significant* trend toward reaching that ceiling **faster** (AUC 0.964 vs 0.950 and time-to-46 ≈1848 vs 3221, both p≈0.16 at n=5). Consistent with your §1/§7 read that "V5's win is cold+floor, not the posterior."
- **But I want to be careful NOT to over-read this as "adaptive is ineffective" — three confounds mean adaptive was never given a fair test here:** (1) **Finding F** — the reward had saturated, and a Thompson-sampling bandit with no reward signal draws ≈uniformly *by construction*, so this is a test of adaptive-with-no-signal, not of adaptive; (2) **the CGC channel was NFP-10-broken** during this run — and CGC is precisely the later-saturating channel where adaptive could plausibly have helped post-local — so the "no extra CGCs" observation is unreliable (the *local*-ceiling result is NFP-10-clean, but the local channel also saturated); (3) this was the **small ~48-arm V5 space the floor already fully covers** — the regime where adaptive matters *least* (it can only re-order pulls, not reach new territory). **So the honest conclusion is: adaptive's value is *untested under fair conditions*, not absent.** This is exactly why D1.E (enriched reward), the Hybrid arm-space expansion, and the NFP-10 fix exist — each removes one of these confounds.
- **Finding F (why):** I only implemented *half* of your §7 Stage-2 — the floor decay, not the enriched reward. The reward (`l_new+g_new+s_new`) **saturates by ~mut 3000–3500** (the local catalog saturates at ~mut 3200), so when the floor decays and adaptive takes over, it has *nothing left to discriminate on*. The null is a reward-saturation result, not a schedule result.
- **Finding E:** in the post-boundary window where the epoch-decay variant's lower floor diverges from static, both discovered **exactly the same contexts (10 vs 10 across 5 seeds)** — directly killing the narrow "the 96% floor starves productive exploitation" hypothesis.
- **Finding D (scheduler geometry):** the integer-per-arm-quota scheduler supports only ~3 floor regimes (~0%/48%/96%) on V5's ~48 arms, so your 3-tier `[0.55,0.35,0.20]` collapses to 2 tiers and *gradual* decay is mechanically untestable here. Fixing it needs either per-mutation Bernoulli floor sampling (≈1 line) or a larger arm count (Hybrid).
- **Reframing for the Hybrid arm-space-dilution risk (important):** since the floor (not adaptive) is what's demonstrably driving discovery *so far*, enlarging the arm space (Hybrid) carries a real risk — if it thins per-arm floor coverage, you could *under-cover* arms (a lower ceiling). **We have no evidence yet that the adaptive MAB would compensate** (it didn't in D1.A — but that was under a saturated reward, so its true value is untested). The conservative planning stance: *don't assume* adaptive will rescue a thinned floor — keep the mappings bounded (Q8) and/or grow the budget to keep per-arm floor coverage adequate — while D1.E and Hybrid are exactly the experiments that finally test whether adaptive (under a non-saturated reward + a bigger arm space the floor can't fully cover) *does* earn its keep. Note `mutation_substrategy_uniqueness` is exploration-like (rewards trying new sub-arms), so an enriched reward could plausibly make adaptive function as a *smarter floor* rather than mere exploitation — but that's a hypothesis to test, not a settled result.
- Decay is **not killed** — it remains a candidate for Hybrid (more arms → finer quotas) and for the enriched reward.
**Surfaces decisions:** keep decay + is the Bernoulli-floor change worth it (§5 Q1); and the dilution reframing feeds the arm-sizing question (§5 Q8) and my Hybrid hypothesis caveat (§4.1).

### 2.2 D1.B — CGC coarsening variants *(your §11)*
**Did:** evaluated `region_only` / `log4` / `page_class` vs production `log2` as the CGC reward signal, post-hoc on the existing corpus.
**Found:**
- **Saturation inversion (the headline):** your §11 hypothesis was that a coarser/semantic CGC bucketing would extend the reward's discriminating window past local saturation. Empirically the **opposite** — coarser variants saturate *earlier* (mut ~1300–1800) than local saturation (~3221) and than production `log2` (~3400). Fewer keys → faster saturation → *shorter* window.
- Even the best L0 (`production_log2`, corrected) has thin post-local headroom (~1 new key / 70 mutations). **L0 schema choice alone cannot fix Finding F.**
- **`page_class` is my concrete ELF-derived definition of your "maybe page_class" hint** — I need you to confirm/correct it (full layout in `D1B_SUBSECTION.md`). It's a useful *analysis* lens but **not** a reward-signal win.
- **Correction (NFP-10):** I found a production bug — the CGC extractor was labeling memory regions with the *word* address instead of the *byte* address, mis-classifying ~53–59% of memory contexts across all prior runs. Fixed; post-hoc replay *reconstructs* the corrected counts from the stored DBs (the DBs themselves still contain the bug). **Your prior R2 conclusions hold in direction** (V5 > V1) but memory-CGC absolute counts were understated ~10–20%.
**Surfaces decision:** confirm CGC reward = `production_log2`; confirm/redirect `page_class` — §5 Q2.

### 2.3 D1.C — bug-proximity metric stack *(your §5)*
**Did:** built the §5 metric stack and searched for *per-mutation* signals that are orthogonal to the existing reward and still fire after local saturation — candidates to enrich the reward (L1).
**Found:**
- **3 strong L1 candidates** that fire post-local with ~99% disjoint-fire from the existing reward bit: `mutation_substrategy_uniqueness`, `d_loc_le_2_flag`, `singleton_failure_flag`. These are the lever D1.A/D1.B lacked. (A 4th, `recent_marginal_discovery_rate`, also passed both gates — the "orthogonality surprise" — but it's continuous, so it's slotted as a scalar-bandit/L2 input per NFP-9 since L1 caps at 3.)
- Your "free" candidate `f_new > 0` (new constraint-family) is **empirically dead post-local** on V5 (fires ~0% after mut 3000).
- **`verifier_accepted_invalid_count = 0` across all A4 runs** — A4's current single-cell catalog produces *zero* accepted-invalids. (Contrast V6 in §3.1.) Quantitative confirmation of your "local coverage is a survey metric, not a bug metric."
- **A genuinely new finding:** `singleton_failure_rate` is the *only* metric on which decay ≠ static — decay produces **~22% fewer singleton failures** (12.9–13.4% vs 16.7%, p ~ 10⁻⁶); **decayexp specifically** also lifts the d_loc tail by +1 (p95 7 vs 6, Wilcoxon p=0.0625 — smallest possible at n=5; decayepoch ties static). So decay measurably alters the failure profile — but **D1.C cannot tell which of two readings holds:** (a) decay finds *richer multi-loc failures* V5-static misses (which is *pro*-decay if those cascades are bug-proximate, *anti*-decay per your §4/§6 prior if they aren't), or (b) decay *misses surgical singleton mutations* entirely (intrinsically anti-decay). The singleton signal wired into L1 in D1.E is the causal test that distinguishes them.
**Surfaces decision:** which L1 signals + composition; does the cascade finding argue against decay — §5 Q1/Q3.

### 2.4 D2.A — Hybrid-V7 foundation
**Did:** the infrastructure for Hybrid V7 — promoted the arm key to the 5-tuple, added `MutationOutcome` + `applied_accounting_mode`, verified write-time loc normalization. A golden-trace test proved V5's behavior byte-identical **across the ArmKey refactor**, so D2's `V5_control` reuses the frozen D1.A archive. **Caveat (post-1.5e):** a *fresh* V5 run is no longer byte-identical to that archive, because D2.B Batch 1.5e made `PRE_EXEC_REG_MOD` RNG-pick its strategy per pull (`fuzzer.py:1686`) — so **D1.E uses a fresh post-rewire V5-static baseline (§4), not the archive.**
**Found / note:** `applied_accounting_mode` is scaffolded but **has never run in a real campaign** — its first use is the V6-cTS/Hybrid runs (a smoke gate is warranted). Given §3.2 (V6 is productive), its stakes are lower than originally assumed.

### 2.5 D2.B — pure-A4 kind expansion *(your Priority 3 / §8)*
**Did:** implemented all 8 pure-A4 mutation kinds you requested, with full attestation (mutation-applied → trace-changed → constraint-fires) and source-level mechanism proofs.
**Found — the headline: only 3 of 8 are LIVE; 5 are mechanism-proven DEAD ARMS on this guest.**
- **LIVE (3):** `TXN_PREV_WORD_MOD`, `TXN_PREV_CYCLE_MOD`, `CYCLE_DIFF_COUNT_MOD` — these mutate fields an extern *returns* to the DSL (→ memory-permutation / cycle constraints).
- **DEAD (5)** via two structural mechanisms: **W-17** (`set_cycle` preset overwritten by execution-derived value: `pc`/`state`/`machine_mode`) and **W-18** (extern reads the field only as a sanity check, never returns it: `txn.addr`/`txn.cycle`). The mutated value never enters the witness → the proof attests the *correct* execution → **not soundness bugs.**
- **Smoking gun:** same extern, one memory transaction, four fields — `prev_word`+`prev_cycle` are returned → LIVE; `addr`+`cycle`-LSB are sanity-only → DEAD. The sole differentiator is whether the extern returns the field.
- **Implication:** A4's catalog ceiling is even narrower than your §2 conclusion that "A4's mutation catalog is now the ceiling" — only 3/8 of your requested kinds are live; the A4 arm space is 11 effective kinds. This sharpens the case for Hybrid over further pure-A4 expansion.
- **But I have a high-confidence next-batch roadmap** (mechanism-selected up front, not guessed): `BIGINT_BYTES_MOD` (bigint operands), paging-cycle kinds, and a *new category* — **structural-index mutation** (corrupt the index *into* a trace array, not a value in it: `CYCLE_TXN_IDX_MOD`, `CYCLE_BIGINT_IDX_MOD`). These hit surfaces no current kind touches. Full analysis in `IV_POS_8_D2_B_MECHANISM_REPORT.md` §11.
- **Campaign-reading caveat (relevant to the §3.1 no-op question):** the fuzzer's "potential bug" counter increments on (applied + trace-changed + verifier-accepts). In the N=100 real-binary smoke it printed **"27 potential bugs"** — which were *exactly* the 27 dead-arm attempts (0 real bugs). So a raw "potential bug" count is a no-op/dead-arm artifact, not a soundness signal — the same confound that affects the V6 accepted set (§3.1).
**Surfaces decision:** pursue the §11 next batch, or declare A4 "done" and pour effort into Hybrid + isolation — §5 Q5.

---

## 3. Cross-cutting findings

### 3.1 The bug-signal asymmetry — and the no-op confound (important)
- **A4 (all variants): 0 accepted-invalids.** Single-cell witness mutations almost always reject.
- **Arguzz (V6): ~2.95% APPLIED+ACCEPTED** (~177 of 6000 per campaign). This is the **only place anywhere in the project that looks like a soundness signal** — but it's **untriaged**, and my prior is that **the large majority are fault-no-ops** (the injected fault didn't propagate, so the proof correctly verifies a *valid* execution). We cannot currently distinguish a fault-no-op from a genuine accepted-invalid — both present as "applied + accepted."
- **The architectural question this raises (I want your call):** Acceptance is *not* in my bandit reward today (reward is coverage-based, so the search already de-prioritizes no-ops). The no-op problem is in the **triage loop** — the soundness flag fires on every applied+accepted, mostly no-ops, so we keep "patching and re-checking" without converging on a real bug. **My proposal:** (a) keep acceptance out of the reward permanently (never reward "accepted," or the fuzzer learns to produce no-ops); (b) instead of chasing every accepted candidate, add a **fault-propagation filter** so we only deep-triage accepted mutations that *demonstrably changed the semantic execution/witness*; (c) run the survey engine broadly across many guests rather than treadmilling on per-candidate triage. This is essentially your Mode-A (survey) / Mode-B (isolation) split. **Do you agree, or would you treat the ~2.95% accepted set differently?** — §5 Q4.

### 3.2 The Arguzz surface is highly productive (corrected)
An earlier internal analysis mis-classified ~95% of Arguzz mutations as "panic/no-op." That was a **classifier artifact** (the driver checked for a panic string *before* checking prover status). Corrected breakdown of a 6000-mutation V6 campaign:
- **94.6% APPLIED** total — of which **91.6% APPLIED+REJECTED** (the prover ran and constraints fired; **~25.6% of these — 1,407/5,497 — reject via the *global* C2 channel with no local `<constraint_fail>` tag**, the V6 analog of an A4 finding) + **2.95% APPLIED+ACCEPTED** (§3.1) — plus only **~5.2% truly skipped** (guest crashed pre-prover) and <0.2% timeout/edge.
- *(Provenance + triage:* this breakdown is under D2.C v0.4's `prover_status`-primary classifier ("Option C"), which recovered the 91.6% bandit signal that a prior `host_panic`-primary classifier had misrouted to ERROR (mechanism in `IV_POS_8_D2_C_SPEC.md` §6.1). D2.C tags the 1,407 Path-B rows with `failure_recording_gap=True` so D2.G can distinguish "rejected via C2 / no local tag" from "applied + accepted" — without that tag they'd look identical to fault-no-ops in post-hoc analysis.)
- **Implication:** the V6 surface gives the bandit **dense applied-pull credit** (94.6%, not no-op-dominated as the old framing assumed), so applied-mutation accounting matters less than I'd assumed. But **94.6% APPLIED ≠ 94.6% rewarded** — the reward is *coverage*-based (§1.4), so whether those APPLIED+REJECTED rows discover *new* coverage past V5's saturation point (vs rediscovering known locations) is **untested**, and is exactly what the §4.1 four-variant comparison measures.

### 3.3 Where this leaves the "can post-execution fuzzing beat Arguzz?" question
Consistent with your §16: pure single-cell A4 yields **0** accepted-invalids and a narrow live catalog; Arguzz yields a productive surface with ~3% accepted candidates. The value of *my* approach concentrates exactly where you predicted — **witness-internal structures Arguzz can't easily reach** (the live A4 kinds touch memory-permutation metadata: `prev_word`, `prev_cycle`, cycle-table counts). The path forward is the hybrid, plus an isolation/triage layer.

---

## 4. The integration plans (D1.E and D2.C — spec only; react to these)

**D1.E — reward-engine integration (A4/V5):** wire D1.B's L0 (`production_log2`, kept) + D1.C's 3 L1 signals (naive OR, capped ≤3, with an opposite-saturation guard since `d_loc_le_2_flag` fires 60.7% post-local — guard threshold 0.75) into `bandit_success`; retune K (≈200–300) and the epoch boundary; re-run V5-static + 2 decay variants (15 jobs). **The causal test:** does enriched reward give the decaying bandit a discriminating gradient that beats static? L2 (scalar bandit) deferred. **Baseline confound (disclosed):** the V5-static here is a *fresh* post-rewire / post-D2.B-1.5e run (not the D1.A archive), which couples the L1 rewire with the `PRE_EXEC_REG_MOD` retrofix into one comparison (Option B per D1.E spec Q-E-RETROFIX-ABLATION; a 10-job Option-C ablation is conditional on v1 ambiguity). **Scope caveat:** D1.C's signals are V5-specific — applying L1 to Hybrid needs a re-audit.

**D2.C — surface integration (A4+Arguzz):** a 3-layer stack (subprocess primitive → bandit bridge → modernized V6-uniform driver) that brings the Arguzz exec-fault kinds into the bandit arm space — **all 11 for V6-cTS, the 4 selected for Hybrid-cTS** (per the §1.2 design note) — and lets V6-cTS/Hybrid-cTS schedule them through the same selector as A4. Outcome mapping is prover-status-primary; the ~2.95% accepted rows get a `soundness_signal` tag for triage. Enables the §9 variant matrix; the actual cross-variant campaigns are the subsequent phases (D2.D–G).

**The convergence (and its open seam):** Hybrid-cTS = D1.E's reward engine ⊕ D2.C's surface, but *neither spec fully specifies that fusion* — and the biggest unspecified question is **whether L1 reward enrichment applies to Hybrid or only to V5.**

### 4.1 My intended *immediate next experiment* (I want your setup guidance)
After your call, my next step is the **§9 four-variant comparison on POS — V6-uniform vs V6-cTS vs Hybrid-cTS vs V5** — to get a strong architecture checkpoint *before* completing the rest of `ProG_Report_3` (witness-patching / repair / Mode-B deferred to after I have initial results).
**My hypothesis:** my constraint-space-exploration advantage (V5's semantic-zone-directed scheduling) carried into Hybrid-cTS should beat flat Arguzz, because Hybrid gets *both* the directed exploration *and* Arguzz's broad mutation terrain. I think this is a strong checkpoint that is plausibly already better than Arguzz-flat.
**The caveat I'm aware of (and want your read on):** your §1/§7 showed V5's win is mostly *deterministic floor coverage*, not the adaptive MAB. Over the bigger Arguzz/Hybrid arm space (Hybrid-cTS ~160–240 arms; **V6-cTS standalone ~200–350 — the larger of the two, near your §9 Q9 "300 arms, consider reducing" advisory**), per-arm floor coverage *dilutes* — so whether the exploration advantage survives the bigger arm space is exactly what this comparison tests. I'll report it with **territory decomposition (common / A4-only / Arguzz-only) + applied-mutation counts** so the "beats Arguzz" claim is fair (your §5).

---

## 5. Decisions I need from you

1. **Decay's fate.** Keep decay and run the V5 causal test (D1.E)? Defer decay to Hybrid only (larger arm space relieves the geometry limit)? Or drop it? And — is the per-mutation **Bernoulli-floor** scheduler change (to make *gradual* decay testable at all) worth doing? *(Weigh the D1.C singleton finding: decay → ~22% fewer singletons — open whether that's richer-cascade-discovery (possibly *for*) or missed-surgical-witnesses (*against*); D1.E's L1 singleton signal is the test.)*
2. **CGC reward.** Confirm `production_log2` as the reward CGC (coarsening is dead per saturation inversion). Confirm or redirect my ELF-derived `page_class` definition.
3. **L1 reward composition.** Naive OR of the 3 signals (≤3, lowest risk) vs a richer composition (per-channel posteriors / weighted / scalar-bandit L2)? *(Note: D1.B called naive OR "redundant" — but that referred to OR-ing two overlapping **CGC** channels; D1.C's 3 signals are orthogonal (~99% disjoint-fire), so OR-ing **them** is not redundant.)* And **does L1 carry to Hybrid** (requires re-audit) or stay V5-only?
4. **The accept signal / no-op confound** (§3.1). Endorse: acceptance stays out of the reward + replace per-candidate chasing with a fault-propagation filter + run broadly (Mode-A/Mode-B split)? Or do you want the ~2.95% accepted set handled differently (e.g. a dedicated triage/repair pass now)?
5. **Pure-A4 next batch.** Pursue the mechanism-selected §11 roadmap (bigint / paging / structural-index kinds) in a future cycle, or treat the A4 surface as "done" and concentrate on Hybrid + the isolation layer (your Priority 2)?
6. **Sequencing.** Run D1.E's V5 reward causal test first, or jump straight to building Hybrid-cTS (D2.C→D2.D) and fold reward enrichment in afterward (with a re-audit)?
7. **Multi-guest sequencing (for the §4.1 four-variant comparison).** Run the four-variant comparison on the **current single guest first** (fast checkpoint), or build a **multi-guest suite first** so the headline isn't guest-specific? If multi-guest, which to prioritize having ready — your §13 listed stock SHA (cheap), ECALL/MRET-heavy (needs a C++ inspector extension → lead time), control-flow, memory-stress, accelerator/Poseidon/BigInt? And do you agree with **deferring witness-patching / repair (your §10 / Priority 2) until after** these initial POS results — i.e. get a strong checkpoint before completing the rest of `ProG_Report_3`?
8. **Are my semantic mappings sound?** I want to confirm the predefined/open mappings are carving along the right distinctions before building the variants, because I don't plan a large empirical trace-by-trace sweep to validate combinations. The mappings: **semantic zones** (circuit major/minor → zone), **arm `opcode_class`** (7-class: arithmetic/memory_load/memory_store/branch/jump/ecall_mret/system) vs **CGC `opcode_class`** (8-class: alu/mul/div/mem/branch_or_ctrl/poseidon/sha/other — intentionally different granularity), **`txn_role`** (6 memory-transaction roles), and **CGC address bucketing** (9 D8 VM regions × log2 bucket, plus my ELF-derived `page_class`). I've validated these by **source-level mechanism reasoning** (the same approach that produced the D2.B dead-arm proofs), NOT by empirical sweeps — **is that validation sufficient, and which mappings would you change?** Tradeoff I'm weighing: finer mappings discriminate more but enlarge the arm space (~160–240 for Hybrid-cTS; ~200–350 for V6-cTS standalone) and slow bandit convergence — I'm inclined to keep the current bounded mappings for the first checkpoint and refine on results.

---

## 6. Attached artifacts (what each is, and why)

**Read-first (self-contained, Pro-facing):**
1. **This doc** — the synthesis + definitions + the decisions I need.
2. `IV_POS_8_NOTES_FOR_PRO.txt` — running architectural-decision log (NFP-1..11); the "why it's built this way" context.

**Per-phase depth (each is a self-contained subsection with its own findings/limitations):**
3. `D1A_SUBSECTION.txt` — decay results, Findings A–F. *(figures: `d1a/plots/01–05_*.png`)*
4. `D1B_SUBSECTION.md` + `d1e_handoff_CGC_saturation.md` — saturation inversion, NFP-10, page_class layout (please confirm). *(figures: `d1b/plots/d1b_saturation_overlay_v5*.png`, `cgc_curve_*.png`)*
5. `D1C_SUBSECTION.md` + `d1c_signal_shortlist.md` — the L1 signals, the §5/§8 metric stack, the singleton-decay finding. *(figures: `d1c/plots/d1c_batch1_fire_rate_*.png`)*
6. **`IV_POS_8_D2_B_MECHANISM_REPORT.md`** — *the key one* — W-17/W-18 dead-arm proofs, the smoking-gun table, the 4-channel model, and the §11 next-batch roadmap.

**The integration plans (react to these):**
7. `IV_POS_8_D1_E_SPEC.md` — the reward-rewire plan.
8. `IV_POS_8_D2_C_SPEC.md` — the Arguzz-integration plan (v0.4 — V6-cTS scope corrected to all 11 Arguzz kinds; Hybrid-cTS keeps the 4 selected; consistent with §1.2 here).

**On-demand (raw evidence, attach if you want to verify numbers):** the executed notebooks rendered to **PDF** at `pro_checkin_attachments/IV_POS_8_D1{A,B,C}_NOTEBOOK.pdf` (D1A and D1B embed their plots; D1C is table/text-heavy — see note), plus the result CSVs.

> **Note on figures (packaging):** the per-phase subsection `.md` files reference their plots by relative path (so the figures don't render from the markdown alone). The cleanest minimal package: send the subsections as text **+** the **D1A/D1B notebook PDFs**, which embed those phases' plots (the saturation-overlay, mode-share, etc.). The only figures *not* in a notebook PDF are D1C's two fire-rate plots (its notebook is table-heavy) — attach `d1c/plots/d1c_batch1_fire_rate_{full,post_local}.png` directly if you want them. Notebook numbers are identical to the subsections; the PDFs are the figure + full-table verification layer.
