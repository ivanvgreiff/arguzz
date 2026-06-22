# IV.POS.8 — Pro Check-in (post-implementation; integration now RAN — see §3.4)

**To:** ChatGPT Pro · **From:** Ivan (+ Cursor-Opus/Composer pairs) · **Date:** 2026-06-19, **updated 2026-06-21**
**Prior context you (Pro) wrote:** `ProG_Report_3.md` (the draft below) and `ProG_Report_4.md` (which prioritized the four-variant experiment §3.4 now answers). This doc uses your nomenclature where possible.

> **Read §3.4 first** for the four-variant campaign results (D2.F + D2.G): verified-negative soundness, Case B coverage, A4-local / Arguzz-global orthogonality, and **two planned next experiments** (multi-guest sweep + known-bug race).

---

## 0. What this is and what I need from you

Since `ProG_Report_3`, I built out two work-streams as **deliberately separate components**, integrated the Arguzz surface (**D2.C**), and ran the four-variant POS campaign Pro prioritized in `ProG_Report_4` (**D2.F** + **D2.G** + **D2.H** territory analysis). **§3.4 is the results layer** — verified-negative soundness, Case B coverage, and the A4-local / Arguzz-global orthogonality. What I need from you now is your architecture call on **what to do next** — especially the **two planned follow-ups** in §3.4 (multi-guest coverage sweep vs known-bug detection race) — plus the still-open reward/decay decisions (**D1.E** remains spec-only).

- **D1** = housekeeping + scheduler/reward tuning (your Priority 4 + the §5/§7/§11 asks).
- **D2** = Hybrid V7 construction (your Priority 1 + 3): foundation, pure-A4 catalog expansion, Arguzz integration, and the four-variant campaign.
- **D1.E** (reward-engine integration for V5) is still **spec only — not yet run.** **D2.C–G are done** (see §1.7).

**You have no access to my repo** — §1 below is a self-contained definitions/nomenclature primer (with source snippets) so every later claim is grounded. §2 is per-phase findings through D2.B. §3 is cross-cutting findings, including **§3.4 campaign results**. §4 records the integration specs (mostly executed for D2.C; D1.E still pending). **§5 is the explicit set of decisions I need from you** — some are now answered by §3.4 (marked inline). §6 lists the evidence attached with this submission (and points back to the material you already have).

### 0.1 Scope & caveats (read before the findings)
- **One guest — and it is _not_ a SHA-2 hash.** Despite the host-harness name **`sha2-host`**, the guest program is a **CircIL-generated metamorphic differential-equivalence circuit** (Arguzz's metamorphic-testing style): it embeds **two integer/boolean circuits, `c0` and `c1`** — metamorphic variants meant to be input-output equivalent — runs both on the same inputs, then **XOR-compares their six outputs** and commits the index of the first divergence (or a `0xDEADBEEF` sentinel if all six match). The instruction mix is plain **u32 arithmetic/logic**: `*`, `+`, `&`/`|` (the bitwise ops via inline RISC-V `asm!`), **`%` → `remu`/`divu` (the `inst_div` family)**, `==`/`>=` compares, conditional selects, and `^` diffs. It is a **3961-step** indexed trace (steps `0…3961`). **This bounds every finding:** (a) circuit families this guest never exercises are simply empty here — `core_sha`, `core_poseidon`, paging/MRET cycles — which is a core reason a second guest matters (Q7); (b) the D2.B "dead arm" classifications are scoped to this guest's **user-instruction cycles** (one dead kind is plausibly *live* on paging cycles), and decay/singleton dynamics could differ on other workloads; (c) the guest's two `%` sites use **distinct** source operands (`var1 % var5`, `const % var23`), so it does **not** contain the `rs1==rs2` pattern of the known soundness bug — exactly why the §3.4-experiment-2 bug race needs a dedicated bug-targeting guest. Multi-guest (your §13) is future work.
- **Decay sample is n=5 paired triplets** (a POS infrastructure failure truncated the planned n=10). Directional, not high-powered.
- **D1.A/B/C are post-hoc analysis on frozen campaign DBs** — they identify *candidates* and characterize properties; they do **not** prove the bandit benefits from learning on them (that's D1.E's forward-run job).
- **Four-variant campaign complete.** Hybrid-cTS, V6-cTS, V6-uniform, and V5_control all ran (D2.F); full accept triage completed (D2.G). Headline results: §3.4.

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
| **D2.C** | Arguzz integration (integration) | Priority 1 (toward §9 variants) | **done** |
| D2.D–F | variant CLI / tests / dispatch / four-variant POS campaign | Priority 1 | **done** |
| D2.G | cross-variant triage + Case A–E + soundness re-read | Priority 1 | **done** (§3.4) |
| D2.H | territory / constraint-space decomposition (pooled local + CGC) | Priority 1 | **done** (§3.4 Result 3) |

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
**Surfaces decisions:** keep decay + is the Bernoulli-floor change worth it (§5 Q1); and the dilution reframing feeds the arm-sizing question (§5 Q8). *(The §3.4 campaign is now the empirical test of Hybrid arm-space dilution — Case B + orthogonality in §3.4.)*

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
**Did:** the infrastructure for Hybrid V7 — promoted the arm key to the 5-tuple, added `MutationOutcome` + `applied_accounting_mode`, verified write-time loc normalization. A golden-trace test proved V5's behavior byte-identical **across the ArmKey refactor**, validating that the foundation is non-perturbing for the V5 path. **Caveat (post-1.5e):** a *fresh* V5 run is no longer byte-identical to the frozen D1.A archive, because D2.B Batch 1.5e made `PRE_EXEC_REG_MOD` RNG-pick its strategy per pull (`fuzzer.py:1686`) — so the §3.4 campaign ran `V5_control` as a **fresh N=10000 run** (3 seeds), not the frozen N=6000 archive (and D1.E, when run, will likewise use a fresh post-1.5e V5-static baseline).
**Found / note:** `applied_accounting_mode` **ran on the Arguzz dispatch path** (V6-cTS and Hybrid's Arguzz arms): SKIPPED/ERROR Arguzz pulls do not advance the scheduler, so no-op injections don't count as bandit pulls (your §8 ask). Hybrid's A4 arms keep the legacy V5 regime (A4 errors still advance). DB check (Hybrid seed 1234): Arguzz-arm scheduler pulls (**3581**) exactly match the Arguzz applied count — confirming the ~5% skips were excluded. Given §3.2 (V6 is ~94.6% applied), the practical impact on the comparison is small.

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
- **Arguzz (V6): ~2.95% APPLIED+ACCEPTED** in the pre-campaign N=6000 runs (~177 per campaign). This was the **only place in the project that looked like a soundness signal** — but it was **untriaged** at the time of the original draft.
- **Post-campaign (§3.4):** the fault-propagation filter is built and all **2795** campaign accepts were classified (**1423** deduped trace reruns). **0 strong / 0 hidden** — the ~3% set is explained by provable no-ops and proof-invisible IWM, not soundness bugs on `sha2-host`. The architectural stance below is **validated**; see §5 Q4.
- **The architectural stance (validated by §3.4):** Acceptance is *not* in my bandit reward (coverage-based). The no-op problem was in the **triage loop** — the soundness flag fires on every applied+accepted, mostly no-ops. **What we did:** (a) keep acceptance out of the reward; (b) add a **fault-propagation filter** for deep triage; (c) treat broad multi-guest survey as the next lever rather than per-candidate chasing. This is your Mode-A (survey) / Mode-B (isolation) split.

### 3.2 The Arguzz surface is highly productive (corrected)
An earlier internal analysis mis-classified ~95% of Arguzz mutations as "panic/no-op." That was a **classifier artifact** (the driver checked for a panic string *before* checking prover status). Corrected breakdown of a 6000-mutation V6 campaign:
- **94.6% APPLIED** total — of which **91.6% APPLIED+REJECTED** (the prover ran and constraints fired; **~25.6% of these — 1,407/5,497 — reject via the *global* C2 channel with no local `<constraint_fail>` tag**, the V6 analog of an A4 finding) + **2.95% APPLIED+ACCEPTED** (§3.1) — plus only **~5.2% truly skipped** (guest crashed pre-prover) and <0.2% timeout/edge.
- *(Provenance + triage:* this breakdown is under D2.C v0.4's `prover_status`-primary classifier ("Option C"), which recovered the 91.6% bandit signal that a prior `host_panic`-primary classifier had misrouted to ERROR (mechanism in `IV_POS_8_D2_C_SPEC.md` §6.1). D2.C tags the 1,407 Path-B rows with `failure_recording_gap=True` so D2.G can distinguish "rejected via C2 / no local tag" from "applied + accepted" — without that tag they'd look identical to fault-no-ops in post-hoc analysis.)
- **Implication:** the V6 surface gives the bandit **dense applied-pull credit** (~94–95% applied at N=10000 in §3.4; the ~94.6% figure above is from the pre-campaign N=6000 run), so applied-mutation accounting is **low-stakes in practice** (§2.4: it did run on the Arguzz path, but skips are only ~5%). **94.6% APPLIED ≠ 94.6% rewarded** — the reward is *coverage*-based (§1.4). The four-variant campaign (§3.4) measured whether Arguzz variants discover territory V5 doesn't; Case B + orthogonality are the headline.

### 3.3 Where this leaves the "can post-execution fuzzing beat Arguzz?" question
Consistent with your §16: pure single-cell A4 yields **0** accepted-invalids and a narrow live catalog; Arguzz yields a productive surface with ~3% accepted candidates. My *pre-campaign hypothesis* (now tested — see §3.4) was that the value of A4 concentrates in **witness-internal structures Arguzz can't easily reach** (the live A4 kinds touch memory-permutation metadata: `prev_word`, `prev_cycle`, cycle-table counts). **The four-variant campaign tested this directly and inverted it: A4's genuine edge is *local* constraint-location breadth, while it is *Arguzz* that reaches more of the global/witness-internal (CGC) structure (§3.4, Result 3).** The path forward is the hybrid (the only variant strong on *both* axes), plus an isolation/triage layer.

### 3.4 Four-variant campaign results — answer to ProG_Report_4's central question
*(D2.F campaign + D2.G triage + D2.H territory decomposition on `sha2-host`.)*

**Setup.** 4 variants × 3 seeds × **N=10000** on the single guest (`sha2-host`). All **2795** accepted proofs across the campaign were put through the **fault-propagation triage filter** — the exact Mode-A/Mode-B-style filter we agreed on in §3.1/Q4, now built. (The 2795 raw accepts dedupe to **1423** distinct fault-identity representatives for the trace reruns; the dedup is kind-aware and fault-preserving — it collapses only byte-identical faults, so the 1423 reruns cover all 2795 accepts.) The filter reruns each deduped accept with a trace and classifies it `noop` (provably inert) / `propagated_candidate` (surface-and-defer) / `hidden_global_reject`. The classifier is source-grounded and **validated with a positive control** (rerunning known-divergent rejected mutations correctly fires the `strong` divergence detector), so its "0 strong" result is a *verified* negative, not a dead detector.

**Result 1 — SOUNDNESS (the headline): zero accepted-invalids in the entire campaign.** Across all 2795 accepts (1423 deduped representatives, all triaged), **0** are genuine soundness candidates (0 `strong` divergences, 0 hidden global rejects; the 110 `propagated_candidate` rows are all conservative **fail-safe** surfacings with **no observed divergence** — 108 proof-invisible `INSTR_WORD_MOD` word mutations and 2 `POST_EXEC_PC_MOD` faults at the final trace step (where the no-op guard has no post-injection window to confirm inertness); separately, 731 of the 733 `POST_EXEC_PC_MOD` accepts are provable `pc→pc+4` no-ops). The ~3% Arguzz "accepted" set from §3.1 is now triaged and explained: it is dominated by **`POST_EXEC_PC_MOD` `pc→pc+4` no-ops** (the injected PC equals the natural next PC; the circuit has no PC-provenance constraint) and **`INSTR_WORD_MOD` proof-invisible mutations** (the circuit re-decodes the *original* committed instruction word, not the executor's mutated local copy). The other 9 Arguzz kinds **reject every committed corruption** (0 accepts) — the circuit is sound against them on this guest. **So on `sha2-host`, neither surface surfaces a soundness bug.** This validates the Q4 stance (acceptance stays out of the reward; the filter replaces per-candidate chasing) and converts the no-op confound into a clean answer.

**Result 2 — COVERAGE, the Case A–E gate: Case B.** On the *authoritative* gate metric (unique **normalized constraint-location territory**, the metric your §5 said to use — NOT raw counts), per seed:

| Variant | norm. locs (n=3) | beats V6-uniform on territory? |
|---|---:|---|
| **Hybrid-cTS** | ~48 | **yes** (+13) |
| V5_control (A4) | ~47 | (reference; ≈ Hybrid) |
| V6-cTS | ~36 | **no — tie** (+1, within seed noise) |
| V6-uniform (Arguzz) | ~35 | — |

⇒ **Case B**: *V6-cTS does not beat V6-uniform; Hybrid does.* The feedback-scheduler hypothesis (cTS > round-robin over the **same** 11 Arguzz kinds) is **not** supported on territory — consistent with your §1/§7 read that the win is floor coverage, not the posterior, and likely aggravated by **arm over-factorization** (V6-cTS ran ~437 arms; the floor can't cover them, so cTS just re-orders pulls without reaching new territory). Hybrid's win is real but is **carried by the A4 surface** (V5 per-seed mean ~47 ≈ Hybrid ~48; pooled local territory is tied at **49** for both; Arguzz contributes only **~1** exclusive normalized loc — `arguzz_only` in territory decomposition).

**Result 3 — the surfaces are ORTHOGONAL; this inverts §3.3.** A4 and Arguzz reach *different* parts of the circuit (D2.H territory decomposition, pooled distinct contexts over 3 seeds — these are *union* counts, so they run slightly higher than the per-seed means in Result 2):

| axis | A4 (V5) | Arguzz (V6-cTS) | Hybrid | V6-uniform (Arguzz baseline) |
|---|---:|---:|---:|---:|
| **local** constraint locs | **49 (most)** | 36 | 49 | 37 |
| **global** CGC contexts | **449 (fewest)** | **670 (most)** | 591 | 565 |

I had predicted (§3.3) that *A4* reaches the global/witness-internal structures. **The data says the reverse: Arguzz reaches the most global (CGC) structure; A4 the least.** A4's genuine edge is *local* location breadth. They are **genuinely orthogonal, not redundant** — and **Hybrid is the only variant strong on both axes** (49 local + 591 CGC). So the honest Hybrid argument is *coverage-completeness across two orthogonal axes*, **not** "Hybrid/A4 beats Arguzz." (Caveat: the V6-cTS > V6-uniform CGC edge — 670 vs 565 — is *not* gating and carries an arm-weighting confound, since cTS over-samples `INSTR_WORD_MOD`; I flag it as unresolved rather than claim it as a feedback win. V6-uniform is included for the canonical Arguzz baseline per §1.1.)

**Caveats (do not over-read).** (1) **Single guest** (`sha2-host`) — every number above is guest-bounded; the orthogonality and Case B may not hold elsewhere. (2) **n=3 seeds → directional only**; the paired tests are sign-consistent across all 3 seeds but the p-values are not computable at n=3 (descriptive, not significant). (3) **0 bugs on one guest is not "the circuit is sound"** — it is "this mutation surface on this guest found nothing," i.e. a coverage/reach result, not a verification result.

**What this tells us — and what I plan next.** The center of gravity moves from "which scheduler wins" (cTS **ties** uniform on the Case gate; the scheduler is not the lever on normalized territory) to **reach and bug-finding power**, which one guest with zero bugs cannot answer. **`sha2-host` answered the integration checkpoint; it cannot answer generalization or detection speed.** I am planning **two separate follow-ups** (not one combined campaign):

**Next experiment 1 — Multi-guest coverage sweep (same RISC Zero, same four variants).** Re-run **V5_control / V6-uniform / V6-cTS / Hybrid-cTS** on several structurally different guest programs — the priority list you gave in `ProG_Report_4` Q7 / `ProG_Report_3` §13 (ECALL/MRET-heavy, memory-stress + control-flow, BigInt/paging, stock SHA, Poseidon/accelerator, etc.). Goal: test whether Case B + the A4-local / Arguzz-global orthogonality from §3.4 are stable architectural facts or `sha2-host` artifacts, and whether dead A4 kinds / empty semantic zones activate on richer guests.

**Questions for you (experiment 1):**
- **Which guests first?** From your prioritized list, which 2–4 should I build/run first given inspector-extension lead time (ECALL/MRET) vs cheap SHA vs BigInt/Poseidon payoff?
- **Presentation:** Should I deliver **per-guest coverage curves** (local + CGC, like D2.H) for each guest, or only headline territory tables per guest?
- **Mega-guest option:** Is it worth crafting **one synthetic guest that mixes** ECALL + memory stress + Poseidon/BigInt paths in a single trace — vs a **small guest set** where each guest isolates one circuit region? Which approach do you prioritize?
- **Budget:** Same **N=10000 × 3 seeds** per guest as `sha2-host`, or a smaller N for the first pass?

**Next experiment 2 — Known-bug detection race (separate from experiment 1).** Check out RISC Zero to a **pre-fix commit with a known soundness bug** (e.g. the Arguzz `remu` / rs1==rs2 class from CVE-2025-52484 territory), run **all four variants (V5_control / V6-uniform / V6-cTS / Hybrid-cTS)** on a **bug-targeting guest**, and measure **time-/pulls-to-first-detection** (and find-rate within budget). I will run the full four-variant set here (not a subset) so the bug-finding comparison is apples-to-apples with the coverage study — even though the historical discovery path was `PRE_EXEC_REG_MOD` during execution, whether A4's post-execution surface can expose this bug is itself part of the question. Current `sha2-host` on the patched tree cannot find this bug by construction; this is the only direct test of *bug-finding power* vs coverage proxy.

**Questions for you (experiment 2):**
- **Guest design:** Minimal hand-crafted guest (e.g. inline-asm `remu` with **rs1==rs2**) vs a richer guest that still contains that pattern — how minimal is acceptable for a clean benchmark?
- **Scale:** How **large** should the guest be (trace length / circuit families touched) so the race is meaningful but not dominated by unrelated noise?
- **Budget:** **N** mutations and **seeds** per variant — match the §3.4 campaign (N=10000, 3 seeds), or use a smaller N with time-to-first-find as the primary metric (coverage on a bug-targeting guest may saturate fast)?
- **Commit choice:** Is **`98387806`** (last state before the #3181 fix) the right benchmark commit, or do you prefer a different planted/known bug?

**Priority between the two:** Which do you want first — experiment 1 (multi-guest generality) or experiment 2 (known-bug race)? I lean toward **experiment 2 first** for a direct bug-finding answer, but experiment 1 may be more important for the paper's coverage story — I want your call.

---

## 4. Integration status (D2.C done; D1.E still pending)

**D2.C — surface integration (A4+Arguzz): DONE.** Built the 3-layer stack (subprocess primitive → bandit bridge → modernized V6-uniform driver) that brings Arguzz exec-fault kinds into the bandit arm space — **all 11 for V6-cTS, the 4 selected for Hybrid-cTS** (per §1.2) — and lets V6-cTS/Hybrid-cTS schedule them through the same selector as A4. Outcome mapping is prover-status-primary; accepted rows carry a `soundness_signal` tag for triage. This enabled D2.D–G and the four-variant campaign.

**D1.E — reward-engine integration (A4/V5): still spec only.** Wire D1.B's L0 (`production_log2`, kept) + D1.C's 3 L1 signals (naive OR, capped ≤3, with an opposite-saturation guard since `d_loc_le_2_flag` fires 60.7% post-local — guard threshold 0.75) into `bandit_success`; retune K (≈200–300) and the epoch boundary; re-run V5-static + 2 decay variants (15 jobs). **The causal test:** does enriched reward give the decaying bandit a discriminating gradient that beats static? L2 (scalar bandit) deferred. **Scope caveat:** D1.C's signals are V5-specific — applying L1 to Hybrid needs a re-audit.

**Open seam:** Hybrid-cTS = D1.E's reward engine ⊕ D2.C's surface, but D1.E never ran — the campaign used the existing coverage-based reward. The biggest open question is **whether L1 reward enrichment applies to Hybrid or only to V5.**

### 4.1 Four-variant comparison — **completed** (results in §3.4)
The **§9 four-variant comparison** Pro prioritized (`ProG_Report_4`) ran on POS: V6-uniform vs V6-cTS vs Hybrid-cTS vs V5_control, 3 seeds × N=10000 on `sha2-host`. **Headline:** Case B (Hybrid wins territory; V6-cTS **ties** V6-uniform); soundness verified-negative; A4-local / Arguzz-global orthogonality inverted the pre-campaign hypothesis. **What remains open:** whether Case B and the orthogonality hold on other guests (§3.4 experiment 1) and which variant finds a known bug fastest (§3.4 experiment 2).

---

## 5. Decisions I need from you

1. **Decay's fate.** Keep decay and run the V5 causal test (D1.E)? Defer decay to Hybrid only (larger arm space relieves the geometry limit)? Or drop it? And — is the per-mutation **Bernoulli-floor** scheduler change (to make *gradual* decay testable at all) worth adopting on the V5/decay path? *(It is already implemented and was used in the V6-cTS/Hybrid campaign runs; V5_control still uses the integer-quota floor.)* *(Weigh the D1.C singleton finding: decay → ~22% fewer singletons — open whether that's richer-cascade-discovery (possibly *for*) or missed-surgical-witnesses (*against*); D1.E's L1 singleton signal is the test.)*
2. **CGC reward.** Confirm `production_log2` as the reward CGC (coarsening is dead per saturation inversion). Confirm or redirect my ELF-derived `page_class` definition.
3. **L1 reward composition.** Naive OR of the 3 signals (≤3, lowest risk) vs a richer composition (per-channel posteriors / weighted / scalar-bandit L2)? *(Note: D1.B called naive OR "redundant" — but that referred to OR-ing two overlapping **CGC** channels; D1.C's 3 signals are orthogonal (~99% disjoint-fire), so OR-ing **them** is not redundant.)* And **does L1 carry to Hybrid** (requires re-audit) or stay V5-only?
4. **The accept signal / no-op confound** (§3.1). **Answered by §3.4:** acceptance stays out of the reward; fault-propagation filter built and validated (0 strong on 2795 accepts). Confirm this stance holds, or do you want a different handling on future guests?
5. **Pure-A4 next batch.** Pursue the mechanism-selected §11 roadmap (bigint / paging / structural-index kinds) in a future cycle, or treat the A4 surface as "done" and concentrate on Hybrid + the isolation layer (your Priority 2)?
6. **Sequencing.** **Partially answered:** Hybrid-cTS is built and ran (§3.4). **Still open:** run **D1.E** (V5 reward rewire causal test) before the next POS sweep, or proceed directly to §3.4 experiments 1–2 and defer D1.E?
7. **Multi-guest sweep (§3.4 experiment 1).** **Partially answered:** single-guest checkpoint done. **Still open:** which guests from your `ProG_Report_4` Q7 list to run first; per-guest coverage curves vs tables only; mega-guest vs isolated guest set; N=10000 vs smaller first pass. *(Full question list in §3.4.)*
8. **Known-bug detection race (§3.4 experiment 2).** **Decided:** all four variants (V5_control / V6-uniform / V6-cTS / Hybrid-cTS), to match the coverage study. **Open:** guest design (minimal rs1==rs2 vs richer); guest size; N and seeds; benchmark commit (`98387806` vs alternative). Priority vs experiment 1? *(Full question list in §3.4.)*
9. **Defer witness-patching / repair?** Do you still agree with deferring your §10 / Priority 2 repair work until after §3.4 experiments 1–2?
10. **Semantic mappings (used in campaign).** Confirm the predefined mappings are sound before scaling further: **semantic zones**, **arm `opcode_class`** (7-class) vs **CGC `opcode_class`** (8-class), **`txn_role`**, and **CGC address bucketing** (+ ELF-derived `page_class`). Validated by source-level mechanism reasoning (same approach as D2.B dead-arm proofs), not empirical sweeps — **is that sufficient, and which mappings would you change?** Tradeoff: finer mappings enlarge the arm space (the campaign ran **258** arms for Hybrid and **437** for V6-cTS — the latter already past your §9 Q9 "≈300 arms, consider reducing" advisory, and the likely driver of the Case B over-factorization in §3.4) and slow convergence.

---

## 6. Attached artifacts (what each is, and why)

**This submission (read in order):**
1. **This doc** — the synthesis + definitions + the decisions I need.

**Four-variant campaign results — the clean, self-contained evidence for §3.4 (read these for the headlines):**
2. `d2g_case_verdict.md` — Case B verdict (normalized-loc gate; CGC non-gating; 0 soundness candidates). *Path:* `a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/`
3. `d2g_soundness_reread.md` — full triage classification (2795 accepts → 1423 deduped trace-reruns; 0 strong / 0 hidden). *Path:* `a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_full/` (CSV sibling `d2g_accept_triage_all_variants.csv`).
4. `D2H_REPORT.md` — pooled local/CGC territory decomposition (§3.4 Result 3 source). *Path:* `a4/runs/iv_pos_8/d2g/`
5. `d2h_exploration.ipynb` — the D2.H notebook: 3 figures (local + CGC coverage curves; total-vs-exclusive territory; per-family discovery heatmap). Rendered copy: `d2h_exploration.html`. *Path:* `a4/runs/iv_pos_8/d2g/`

**Already in your hands — *not* re-attached (referenced by name only so the story stays traceable; these are the materials you used to write `ProG_Report_4`):** `IV_POS_8_NOTES_FOR_PRO.md` (the NFP-1..11 decision log), the **D1.A / D1.B / D1.C** subsections + handoffs (decay, saturation-inversion, the L1 signals), and `IV_POS_8_D2_B_MECHANISM_REPORT.md` (the dead-arm proofs + 4-channel model). The internal build/validation specs (`IV_POS_8_D1_E / D2_C / D2_F / D2_G_SPEC.md`) are engineering logs — available on request, not part of this package.
