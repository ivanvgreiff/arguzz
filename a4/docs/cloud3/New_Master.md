# New Master Plan — IV.POS.9 (governed by `ProG_Report_5.md`)

**Status:** ACTIVE — authoritative forward plan for the post-D2.H phase. **Date:** 2026-06-21. **Author:** Opus (planning).
**Governing requirements:** [`ProG_Report_5.md`](./ProG_Report_5.md) — Pro's steer after the four-variant checkpoint (Case B). *Every track below traces to a section of that report.*
**Backward-looking record:** the IV.POS.8 work (D2.A–H, four-variant Case-B checkpoint) is complete; its master is [`../cloud2/New_Master.md`](../cloud2/New_Master.md) and the Pro-facing synthesis is [`../cloud2/IV_POS_8_PRO_CHECKIN.md`](../cloud2/IV_POS_8_PRO_CHECKIN.md).
**Pre-existing scoping (partial, accuracy not fully verified):** [`../cloud2/IV_POS_8_BACKPORT_SCOPING.md`](../cloud2/IV_POS_8_BACKPORT_SCOPING.md) — D2-Opus's back-port scoping; useful for Track A's first steps. Its **guest shape (`rs1==rs2`) is correct**; its mutation framing is corrected to **read-divergence** (§2.3, now resolved from source).

---

## 0. How this document works (the planning hierarchy)

```
ProG_Report_5.md   →   New_Master.md   →   per-step SPECS   →   per-spec BATCHES
(requirements)         (this doc:           (IV_POS_9_*_SPEC.md:   (composer/*_KICKOFF + *_REPORT:
                        the two tracks,       what each step          Composer implements,
                        what each spec         designs + its           Opus reviews, batch by batch)
                        accomplishes +         batches)
                        its batches; links)
```

- **New_Master (this doc)** = the plan. It says *what each spec accomplishes and the batches that make it up*, the `ProG_Report_5` source, and sequencing. It is deliberately *less* detailed than the specs. **It does not implement anything.**
- **Specs** (`IV_POS_9_<step>_SPEC.md`) = per-step implementation design; outline what each batch does. Each spec is Ivan+Opus reviewed before Composer starts. **These are written later, one at a time** — this master only outlines what each must contain.
- **Batches** (`composer/<step>_BATCH<n>_*.md`) = the most detailed level; Composer implements one batch, Opus reviews, then the next.

**Scope of this master (Ivan's directive):** there are exactly **two things that matter** and they are investigated in depth here:
> **Track A — the known-bug detection race** (the security claim), and **Track B — the multi-guest coverage sweep** (the generalization claim).

Everything else (V6-cTS-lite, D1.E, the mega-guest, repair/Mode-B) is mentioned only briefly in §6 and is **explicitly out of scope** for detailed planning until the two tracks are designed.

> ## 🧭 PLAN OF RECORD (2026-06-23 — current sequencing; OCP/Track A)
> The complementarity table has **two halves**; we build/run them as a pair, A4-side first:
> 1. **A4-side bug — DONE & certified.** `AP/Seam-B`: a planted `VerifyOpcode` decode underconstraint that A4's `INSTR_TYPE_MOD` finds and that is *off Arguzz's surface* (`AP_SEAMB_RESULT.md`; the value-changing A4 bug is impossible — `AP_SEAMB_OPTION_B_ANALYSIS.md`). Binaries archived read-only (`a4/builds/ap_seamb/{control,bench-verifyopcode}`).
> 2. **A4-side RACE — RUNNING (first POS campaign).** Spec [`IV_POS_9_A3_SEAMB_RACE_SPEC.md`]: 4 variants race on the Seam-B binary, **no stop-on-first-bug**, markers = find-prob / first-find-idx (KM CDF) / find-density / conditional-density. **Status (2026-06-24):** A3.1 green; A3.2 smoke green; **A3.3 thesis (N=5000 × 4 × 10) RUNNING on POS** (8 EPYC nodes; complementarity holding — A4/Hybrid find it, Arguzz 0); **A3.4 analysis pipeline built** (`race_lib.py` + notebook + artifact, regenerates at CHAIN_COMPLETE).
> 3. **Arguzz-side bug (`rs1==rs2` CVE) — STARTED IN PARALLEL while A3 runs.** Spec [`IV_POS_9_A1_VULN_BUILD_SPEC.md`] (v0.2). **Status (2026-06-24):** **G1/G2 source gate PASSED** (`98387806` lacks `load_rs2`, in-tree vuln circuit committed — no zirgen regen, unlike the *separate* AP track); trigger contract written; **A1.B1 MODE-2 existence proof RUNNING** (canonical docker env). Then A1.B2 (vuln MODE-1 build + fingerprint) → A1.B3 (deterministic coherent repro, G4/G5) → A2 (race guests) → reuse the A3 harness for the CVE race (there the propagation triage / strong journal oracle IS primary). A1 stays **isolated** from A3/Track-B/AP (own clone, own target-dir, no POS).
> 4. **Headline = the complementarity PAIR** (A4 finds decode/local; Arguzz finds value/global), never either half alone.
> Track B (multi-guest sweep) is owned by a **separate OCP**; this OCP owns Track A + binary-provenance/contamination guarding (L14).

**Pro's top-level sequencing call (`ProG_Report_5` §0/§3/§7 — the north star):**
> *Run the known-bug race **first**, then the multi-guest sweep. Treat them as **two different claims** (bug-finding effectiveness vs coverage generalization) — do not collapse them into one giant experiment. The race comes first because it directly tests whether the coverage proxy has predictive value for real soundness discovery.*

**The thesis claim Pro endorses (`ProG_Report_5` §4.5 — frames both tracks):**
> *Constraint-space feedback and semantic witness-fault scheduling expose **complementary local/global** regions of the RISC Zero constraint system. A **hybrid A4+Arguzz** architecture provides broader attack-surface coverage than either surface alone, and known-bug experiments evaluate whether this coverage translates into **faster soundness-bug discovery**.* — **NOT** "MAB beats Arguzz."

---

## 1. Standing decisions LOCKED by `ProG_Report_5` (constraints all specs must honor)

These are Pro's answers; specs do **not** re-litigate them.

| # | Decision (locked by ProG_Report_5) | Source |
|---|---|---|
| **L1 — Sequencing** | **Bug race first, multi-guest sweep second.** Two separate claims, two separate campaigns. | §0, §3, §5, §7 |
| **L2 — Variant set** | **All four variants** (`V5_control`, `V6_uniform`, `V6_cTS`, `Hybrid_cTS`) in **both** tracks. A negative A4 result is a finding, not a failure. | §3.4, §2.4 |
| **L3 — Bug-guest design** *(CORRECTED — supersedes ProG §3.1 on the mechanism; see §2.3 + [`BUG_MECHANISM_VERIFIED.md`](./BUG_MECHANISM_VERIFIED.md))* | Use a **bug-targeting product-program guest** (Race-guest B) + a minimal microbenchmark (Race-guest A). **The guest must ENCODE `rs1 == rs2`** (same source-register index, e.g. `remu x3,x5,x5`, `x5≠0`, honest `x5%x5=0`) — *verified from the #3181 source: the hole exists only on the same-register path.* The **exploit fault makes the two same-cycle reads of that register DIVERGE** (read#1 ≠ read#2) — **NOT** "set `rs2:=rs1`" (a no-op on an already-equal op; Pro's framing). Force real `remu`/`divu` via inline asm; block constant-folding/immediate-lowering; **disassemble the compiled ELF to confirm an op with identical `rs1==rs2` register fields actually survived**; compare vs a reference; commit OOPS/SUCCESS. *(Pro's surviving valid point: the **mutation** must not be a no-op — here that means read-divergence, not `rs2:=rs1`.)* | §3.1, §3.2, §6 + source |
| **L4 — Bug oracles (two)** | Report **two** oracles: (a) **strong application-level** (proof accepts but journal/public output is wrong / OOPS; post-fix rejects) — the headline vs Arguzz; (b) **internal trace-soundness** (proof accepts but trace/witness violates instruction semantics under a replay checker; post-fix rejects) — fairer to A4's post-execution surface. | §3.8 |
| **L5 — Commit choice** *(now partly verified)* | `98387806` is **confirmed vulnerable at source level**: it lacks `fn load_rs2` and issues two separate `load_register(rs1)`/`load_register(rs2)` reads (the #3181 fix is absent); our base `ebd64e43` has the fix. The vulnerable rv32im **circuit is committed in-tree as generated code** (regenerated by #3181), so building at `98387806` yields the vulnerable circuit **without an external Zirgen fetch** — this largely resolves Pro's "the Zirgen dep may already be patched" worry **provided the build uses the in-tree generated files (no codegen-from-newer-zirgen at build — A1 must confirm)**. The deterministic pre-fix-accepts/post-fix-rejects repro remains the final gate. *(Note: `98387806`'s own commit message is an unrelated CI change — "Replace 3090_ti jobs with 4090," #3171; it is merely a pre-fix checkpoint that happens to carry the vulnerable source. The label is incidental — the source-invariant (G1) + repro (G4/G5) are the authority.)* (Bug affected risc0-circuit-rv32im 2.0.0–2.0.2.) | §3.5 + source |
| **L6 — Race metrics** | Primary = **bug-finding** metrics, not coverage: `find_rate_within_budget`, median pulls- and wall-clock-to-first-**confirmed** bug, Kaplan-Meier survival over pulls, area-under-discovery-curve. Decompose `P(find)=P(select bug-op)·P(apply bug-mutation)·P(diverge)·P(accept)`. | §3.7 |
| **L7 — Multi-guest design** | **A small suite of focused guests**, each isolating one constraint region — **not** one mega-guest as primary evidence. Mega-guest = appendix/robustness only. Show **per-guest curves + tables + a cross-guest heatmap + rank-stability**. | §2.1, §2.3, §2.5, §6 |
| **L8 — Guest priority** | Baseline (current `sha2-host`) anchor + **3 new focused guests**: ECALL/control-heavy, memory-stress+branch/control, accelerator/Poseidon/BigInt. Stock-SHA only if cheap. Bug guest is separate (Track A, race-only). | §2.2 |
| **L9 — Budgets** | **Race:** Stage-0 deterministic (tiny) → Stage-1 smoke (4 variants, 3 seeds, N=2000) → Stage-2 thesis (4 variants, **≥10 paired seeds**, N=5000, **stop-on-first-confirmed-bug**, extend censored runs to N=10000) → Stage-3 optional (20 seeds, N=10000). **Sweep:** Stage-1 screening (4 guests, 4 variants, 3 seeds, N=5000) → Stage-2 thesis on the 2 most informative guests (10 seeds, N=10000). | §2.4, §3.6 |
| **L10 — Reward** | **Acceptance is NEVER a bandit reward** (validated by the 0-strong triage). For the race, reward target-attempts / coverage / confirmed semantic divergence — never raw acceptance (that selects no-ops). | §4.4 |
| **L11 — Architecture carry-forward** | `Hybrid_cTS` = primary broad explorer; `V5_control` = companion local-depth explorer (do **not** retire it — Hybrid slightly dilutes rare A4-only locs); `V6_uniform` = canonical Arguzz baseline; `V6_cTS` = scheduler ablation. | §4.1, §7 |
| **L12 — Deferrals** | **V6-cTS-lite** (arm-space simplification) only **after** the race, and only if V6-cTS underperforms V6-uniform while over-concentrating. **D1.E** reward-rewire is **not** next critical path — run it later only if the race/sweep show reward saturation or persistent A4-local-depth misses. | §4.2, §4.3 |
| **L13 — Commit assignment** *(Ivan-emphasized; our addition, not Pro's)* | **The vulnerable commit (`98387806`) is used by Track A (bug race) ONLY.** Track B (multi-guest sweep) **and all coverage work** run on the **current patched tree** (`28e53771` / base `ebd64e43`) — the same build as the D2.H checkpoint, for cross-guest comparability. **Mixing the two is correctness-fatal** (a race on the patched build finds nothing; a sweep on the vulnerable build silently changes the circuit). *ProG_Report_5 discusses the vulnerable commit only for the race (§3/§3.5/§5 Step 1) and segregates the bug guest as "race rather than coverage generalization" (§2.1); it assigns no commit to the sweep.* Enforced per-run by L14 + G10–G13. | ProG §2.1/§3/§5 + Ivan |
| **L14 — Binary & guest provenance** *(Ivan-emphasized; our addition)* | **No smoke/POS run is trusted on faith — every run must prove which binary and which guest it used.** Each `risc0-host` build embeds a machine-readable **fingerprint** (the `workspace/risc0-modified` HEAD SHA, a `load_rs2`-present flag = vulnerable-vs-patched, an A4-instrumentation hash, and the embedded **guest image ID** `RISC0_GUEST_ID`). The dispatcher **asserts the deployed binary's fingerprint == the intended build** *before* launching, and the fingerprint is **recorded into every run's DB row**. Race runs assert the **vulnerable** fingerprint (+ positive repro); sweep runs assert the **patched** fingerprint (+ negative repro: the bug does NOT reproduce). See gates **G10–G13**. | Ivan |

---

## 2. Pre-flight reality check (grounded in the codebase — read before any spec)

This section records what the infrastructure **actually** supports today, so the specs are designed against reality, not the paper. Findings are from a read-only audit of the repo (MODE 1 = `a4/`; MODE 2 = `projects/risc0-fuzzer/`).

### 2.1 What already exists (reuse)

- **Two fuzzing modes.** **MODE 1** = the `a4/` framework that schedules the 4 variants on a *fixed* embedded guest (`a4/standalone/cli.py`, `v6_uniform_driver.py`, `variants.py`). **MODE 2** = the original Arguzz random-program fuzzer (`projects/risc0-fuzzer/`, `libs/zkvm-fuzzer-utils/.../fuzzer.py`).
- **MODE 2 is largely ready for the bug commit.** `98387806` is already in `RISC0_AVAILABLE_COMMITS_OR_BRANCHES` (`projects/risc0-fuzzer/risc0_fuzzer/settings.py`), with a **frozen vulnerable `rv32im.rs`** at `injection_sources/rv32im_rs_9838780.py`, a metamorphic **`0xDEADBEEF` output oracle**, and an output-divergence soundness check. This is the cheapest path to *prove the bug exists and re-find it with baseline Arguzz*.
- **The weak oracle exists.** MODE 1 tags `soundness_signal=True` when an Arguzz fault is applied and the prover still reports `success` (`a4/standalone/arguzz_invoke.py::_classify_outcome`). The campaign DB records `verifier_accepted`.
- **A coarse trace-replay triage exists.** `a4/runs/iv_pos_8/d2g/propagation_triage.py` reruns an accept with `--trace` and classifies post-inject PC/trace-hash divergence (the basis for the "internal" oracle), validated with a positive control.
- **Guest build/embed pipeline exists.** Guest = compile-time-embedded ELF (`workspace/output/methods/build.rs::embed_methods()`); host reads inputs via CLI flags → `ExecutorEnv` (`workspace/output/host/src/main.rs`). Swapping a guest = edit guest `main.rs` + matching host `Args` + `cargo build` + re-bundle.
- **Per-guest inspection is automatic.** At campaign start the framework runs the host with `A4_INSPECT=1`, parses the trace into `InspectionData`, and (re)builds `classify_zones` + `SemanticArmUniverse` from *that guest's* trace (`a4/standalone/fuzzer.py`, `semantic_arm_universe.py`). Empty `(kind,zone)` arms auto-prune. **So arm universes regenerate per guest with no code change.**
- **The D2.G/D2.H analysis derives loc/CGC from the DB**, so the core metrics/territory/triage logic is largely guest-agnostic.

### 2.2 What is MISSING and must be built (the real work)

| Capability | Status | Needed by |
|---|---|---|
| Instrumented build at the **vulnerable** commit `98387806` | **MISSING** — current tree (`workspace/risc0-modified` @ `28e53771`) sits on the **post-fix** base `ebd64e43`; the campaign found 0 bugs *by construction*. | Track A |
| **Targeted same-register dual-read-divergence mutation (coherent/propagating)** | **MISSING** — the exploit needs a **coherent** witness: `read_rs2` diverged from `read_rs1` **and** the result recomputed to match the diverged operand, so only the *missing* same-register memory constraint is violated while the *present* local-compute constraint holds. This is what a **during-execution (propagating)** fault produces; a **single post-execution read-cell edit does NOT suffice** (it leaves the result stale → trips local-compute → rejected). A deterministic trigger needs the propagating operand mutation (or a coordinated read+result edit) targeting the rs2-read of the `rs1==rs2` op. *(NOT "set `rs2:=rs1`" — a no-op on an already-equal op.)* | Track A |
| **Strong journal oracle** (accept + wrong public output) | **MISSING** — the host decodes the journal (`Receipt Decoder` record) but the harness never captures/compares it across baseline vs fault. | Track A (L4a) |
| **Full trace-soundness oracle** (reg/mem-value replay, not just PC/hash) | **PARTIAL** — `propagation_triage` is coarse (`{step,pc,instruction,asm}`, no reg/mem values; `*_REG_MOD` original-value tags are hardcoded). | Track A (L4b) |
| **Bug-targeting guest(s)** | **MISSING** — current guest's two `%` sites use distinct operands; no `rs1==rs2` site. | Track A |
| **Guest-aware dispatch** (run-id slug, manifest generator, per-guest host bundle/args) | **NEEDS PARAMETERIZATION** — `generate_d2f_manifests.py` hardcodes one `GUEST_ARGS`, one host path, no guest slug in run IDs. | Track B |
| **Guest-aware + cross-guest analysis** | **NEEDS PARAMETERIZATION + NEW aggregation** — `d2h_lib.py` hardcodes prod dirs/run names; `territory.py` hardcodes the `V5_ECALL_MRET_SIGNATURE` loc set; no per-guest/cross-guest aggregation layer. | Track B |
| **ECALL/MRET/paging zone classification** | **MISSING (classifier gap)** — `zone_classifier.py` classifies `pre_ecall`/`post_ecall` but **never** `pre_mret`/`post_mret`/`pre_halt`/`post_halt` (all fall under `major=7`); paging cycles aren't bucketed. **Not a separate C++ binary** — it's extending the Python classifier (decode the instruction word from `--trace`) and/or adding `A4_INSPECT` tags in witgen. | Track B (the priority ECALL/control guest) |
| Host input ABI re-sync per guest | **NEEDS NEW CODE per guest** (hand-synced `env::read` ↔ host `Args`). | Track B |

### 2.3 ✅ RESOLVED FROM SOURCE — the bug mechanism (was the #1 design risk)

The bug-trigger design was the single most important open question, with three sources disagreeing. **It is now resolved by direct inspection of the risc0 #3181 fix** (full evidence + commands in [`BUG_MECHANISM_VERIFIED.md`](./BUG_MECHANISM_VERIFIED.md)). Verdict:

- **The bug is a same-source-register (`rs1 == rs2`) double-read soundness hole.** The #3181 fix's hand-written change adds `fn load_rs2`: when `decoded.rs1 == decoded.rs2` it reads the register **once** and reuses the value; otherwise it reads `rs2` separately. The companion `preflight.rs` change adds `ensure!(txn.cycle != txn.prev_cycle)` — literally "disallow memory I/O to the same address in the same memory cycle." So pre-fix, an `rs1==rs2` op did **two unconstrained reads of one register in one cycle**, and a malicious prover could make them **disagree**.
- **`GPT_Bug_Opinion.md` is CORRECT; `ProG_Report_5` §3.1 is WRONG.** The guest must **encode `rs1==rs2`** (e.g. `remu x3,x5,x5`), and the exploit is **read-divergence** (read#1 ≠ read#2). Pro's "normal `rs1!=rs2`, fault sets `rs2:=rs1`" is wrong on two counts: a `rs1!=rs2` guest never exercises the vulnerable path, and "set `rs2:=rs1`" alone yields the *correct* answer (`x%x`) — no exploit. **`IV_POS_8_BACKPORT_SCOPING.md`'s guest shape was right; its mutation framing needed the divergence correction.**
- **`98387806` is confirmed vulnerable at source level** (`fn load_rs2` absent; two separate `load_register` reads present), and the vulnerable circuit is committed **in-tree** as generated code.

**Pro's one surviving valid point:** the *mutation* must never be a no-op. On an `rs1==rs2` guest, the no-op to avoid is "set `rs2:=rs1`"; the correct mutation is **read-divergence** (L3 reflects this).

**The MODE-2 repro is now a CONFIRMATION GATE, not the arbiter of an open question.** A1 still runs the MODE-2 vulnerable injector (`rv32im_rs_9838780.py`) to produce a deterministic pre-fix-accepts / post-fix-rejects repro — but to *confirm* the now-known mechanism end-to-end and pin the exact witness-cell to target, not to discover what the bug is. A2's guest+mutation are built to the verified design above (and re-checked against the A1 repro).

### 2.4 Other flagged risks

- **Coverage numbers are not comparable across commits** (the bug-commit circuit has a different EQZ/loc universe — per the scoping doc). The race must use **bug-finding metrics** (L6), not coverage deltas, and must **not** be compared to the patched-tree D2.H coverage numbers.
- **Back-port accuracy:** the scoping doc's "~1–2 h, 49/60 byte-clean" is plausible but **unverified end-to-end** (and it doesn't address the Zirgen/`zkvm` dependency-version question Pro raised in L5). Treat A1-B1 as "attempt the transplant; the build + repro is the gate," not "1–2 h is guaranteed."
- **During-execution random reg corruption is a low-probability trigger.** For a *fair* race the bug-relevant arm must be *reachable and selectable* by every scheduler; A2 must ensure the bug-op/field is in the arm space and that the targeted mutation (or a sufficiently dense random one) can hit it within budget — otherwise the race measures luck, not scheduling.
- **Compute reality (not yet quantified in the plan).** At ~2.7 s/mutation (≈ the D2.H rate; ~5.5–9.2 h per N=10000 run): the **race** Stage-2 (4 variants × 10 paired seeds × N=5000, stop-on-first-bug truncates many) is on the order of **~10² run-hours**, but the **sweep** is the expensive part — Stage-1 screening (4 guests × 4 variants × 3 seeds × N=5000) ≈ **~180 run-hours**, and Stage-2 thesis (2 guests × 4 variants × 10 seeds × N=10000) ≈ **~600 run-hours**. Total well into **~10³ core-hours**. This is why Pro's staging exists, but the plan should state it: the sweep likely needs **parallelism across machines** (the cheaper-machine option Ivan was scoping) and the down-select after screening is load-bearing for feasibility. Each run is CPU-only, ~5 cores, ~0.3 GB RAM, x86-64 (per the earlier specs probe) — embarrassingly parallel across runs.

### 2.5 ✅ Validation gates — "are we actually doing this correctly?" (Ivan's explicit ask)

Each gate is a **hard pass/fail** that blocks the next step. These exist so the race cannot silently run on a non-buggy build, a no-op mutation, or a benchmark that measures luck. Specs must implement these as automated checks, not prose.

| # | Gate | Concretely | Blocks |
|---|---|---|---|
| **G1 — commit is vulnerable (source)** | The chosen commit lacks the fix | `git show <commit>:…/execute/rv32im.rs` has **no `fn load_rs2`** and shows two separate `load_register(rs1)`/`load_register(rs2)` reads. (Already true for `98387806`.) | A1.B2 build |
| **G2 — circuit is the in-tree vulnerable one** | No newer Zirgen pulled at build | Confirm the rv32im circuit compiles from the **committed generated files** at the chosen commit (no codegen step fetching a patched Zirgen); the built `risc0-host` embeds the vulnerable constraint set. | A1.B2 |
| **G3 — guest truly encodes `rs1==rs2`** | The compiler didn't fold/realloc it away | **Disassemble** the compiled guest ELF (`objdump`/`riscv… -d`) and find an executed `remu`/`divu` whose **rs1 and rs2 fields are the same register index**. Reject the guest if `a%a` was constant-folded to 0 or emitted with two distinct registers. | A2.B1 |
| **G4 — deterministic positive repro (pre-fix accepts wrong)** | The mechanism actually fires | A hand-specified read-divergence fault on the G3 op makes the **pre-fix build ACCEPT a proof whose committed output/OOPS is wrong**. | A1.B3 (gates A2/A3) |
| **G5 — deterministic negative repro (post-fix rejects)** | The fix actually closes it | The **identical** witness/fault is **REJECTED** by the post-fix build (our current `ebd64e43` tree, which has `load_rs2`). | A1.B3 |
| **G6 — mutation is coherent, not a no-op** | The fault changes the result AND only the missing constraint is violated | The targeted mutation produces read#1 ≠ read#2, a **recomputed** committed result consistent with the diverged operand (so the *present* local-compute constraint still holds), and a result that differs from the honest run. A no-op (`rs2:=rs1`) or an incoherent single-cell edit (stale result → trips local-compute) must be detected and excluded from "confirmed bug." | A2.B3 |
| **G7 — bug-op is selectable by every scheduler** | Fair race, not luck | The bug-relevant (op, field) is a registered, reachable arm for V5/V6_uniform/V6_cTS/Hybrid; log per-variant selection rate so a 0-selection variant is reported as "couldn't target," not "couldn't find." | A2.B3 |
| **G8 — confirmed-bug definition** | One precise success criterion | A run counts as "found the bug" **iff**: targeted op hit → reads diverge → committed output wrong (strong oracle) OR replay-checker flags read inconsistency (internal oracle) → **and** post-fix rejects the same witness. Anything else (no-op accept, unrelated accept) is **not** a find. | A3 metrics |
| **G9 — MODE-2 external sanity** | Independent confirmation | The original Arguzz MODE-2 injector (`rv32im_rs_9838780.py`) re-finds the bug at the same commit — an independent check that the target is genuinely vulnerable and the trigger shape matches G3/G4. | A1.B1 |
| **G10 — build fingerprint exists** | Every binary is self-identifying | Each `risc0-host` embeds + emits (e.g. on an inspect/`--version` path) a fingerprint: `workspace/risc0-modified` HEAD SHA · `load_rs2`-present flag (vulnerable vs patched) · A4-instrumentation hash · embedded guest image ID (`RISC0_GUEST_ID`). | A1.B2 (race build) + the patched build |
| **G11 — per-run binary assertion** | Right binary, every single run | Before **every** smoke/POS batch the dispatcher reads the deployed binary's fingerprint and asserts it == the **intended** build for that experiment (vulnerable for race, patched for sweep); mismatch **aborts**; the fingerprint is written into **every** run's DB row for post-hoc audit. | every race + sweep run |
| **G12 — sweep is the patched build (symmetric to G1/G4)** | A sweep can never silently run the vulnerable binary | **Per run (cheap):** assert the **patched** fingerprint (`load_rs2` present) via G11/G13 — this alone catches a vulnerable binary. **Per build/deploy (defense-in-depth, not per run):** a behavioral negative — the A1 read-divergence repro is **REJECTED** by the deployed patched binary (bug absent). A sweep build that reproduces the bug, or any sweep run whose fingerprint is not the patched one = **hard failure**. *(The full proof-repro runs once per deployed build, not on every one of the ~80 sweep runs.)* | per-run fingerprint; per-build behavioral |
| **G13 — guest identity per run** | Right guest, every run (no multi-guest mixups) | Each run records the embedded guest image ID (`RISC0_GUEST_ID`) and asserts it == the **intended** guest for that job. | every multi-guest + race run |

> **G1–G9 validate the build/mechanism *once* (at A1); G10–G13 are the *per-run* provenance gates that make that validation stick across every later smoke/POS run, on every machine, with two builds (vulnerable + patched) coexisting.** This is the discipline that guarantees "the binary running is the binary we think it is" for **both** tracks — and the symmetric G12 specifically prevents the multi-guest sweep from ever running the vulnerable commit (L13).

---

## 3. TRACK A — Known-bug detection race (PRIORITY; runs first) — *ProG_Report_5 §3, §5 Step 1*

**Goal:** answer the bosses'/thesis security question — *for a real known RISC Zero soundness bug (CVE-2025-52484, the `remu`/`divu` missing-`rs1==rs2` constraint), can each variant find it, and how fast relative to baseline Arguzz?*

**Three specs, run in order. A1 is a hard gate for A2/A3.**

> **The race needs a target A4 can find — that is Spec AP** ([`IV_POS_9_AP_PLANTED_ISREAD_SPEC.md`](./IV_POS_9_AP_PLANTED_ISREAD_SPEC.md), [`PLANTED_BUG_FEASIBILITY.md`](./PLANTED_BUG_FEASIBILITY.md)). The verified mechanism analysis predicts pure-A4 likely **cannot** find the CVE (it needs a coherent/propagating witness). To still give A4 a fair race, AP **plants a faithful register-read-consistency underconstraint** (remove `IsRead` on the `ReadReg` path) on a *separate, patched-tree* build (`bench-isread`) — found by A4 (`PRE_EXEC_REG_MOD next_read`, the empirically-verified (0,1,0) seam, internal oracle) **and** Arguzz (during-exec reg mod, strong oracle). **Separate binaries per bug** (CVE on `bench-cve`, planted on `bench-isread`) — combining them contaminates per-bug attribution and the brackets (rationale in AP §2.3). The race (A3) then runs each variant against each single-bug build and reports per-bug find-rates. AP is independent of A1 (no back-port) and can build in parallel.

### Step A1 — Vulnerable build + commit validation + deterministic repro
**Spec (to write):** `IV_POS_9_A1_VULN_BUILD_SPEC.md`
**Accomplishes:** produce a **trusted vulnerable target** and **confirm the now-verified mechanism end-to-end** (§2.3 / [`BUG_MECHANISM_VERIFIED.md`](./BUG_MECHANISM_VERIFIED.md)) — A1 *confirms and pins the exact witness cell*, it no longer *discovers* the mechanism. Deliverables: (a) MODE-2 Arguzz re-finding the bug at the commit (independent sanity — **G9**); (b) an **instrumented MODE-1 `risc0-host` built at the vulnerable commit** (back-port per the scoping doc), passing **G1** (source lacks `load_rs2`) and **G2** (in-tree vulnerable circuit, no newer Zirgen pulled); (c) a **deterministic repro** — a hand-specified read-divergence fault on an `rs1==rs2` op that the **pre-fix build accepts as a proof of a wrong result** (**G4**) and the **post-fix build rejects** (**G5**).
**Batches (outline):**
- **A1.B1** — MODE-2 existence proof (**G9**): build risc0-fuzzer at `98387806`, drive the `rs1==rs2` path via the frozen `rv32im_rs_9838780.py` injector, confirm the soundness oracle fires; record the canonical trigger (op shape + which read-value is diverged + how accept-of-wrong manifests). *Cross-checks the verified mechanism; pins the exact cell for A2.*
- **A1.B2** — Get an **instrumented + vulnerable** `risc0-host`. The spec must evaluate **two routes** and pick the lower-conflict one: **(i) forward-port** the A4 instrumentation onto `98387806` (tested last turn: ~49/60 files byte-clean, residue = `steps.cpp` assert-wrap regex + 3 small Rust merges); or **(ii) revert the #3181 fix on our current instrumented tree** (swap the executor `load_rs2` + the regenerated circuit files back to their pre-fix versions). *Note:* reverting only the 17-line executor is **insufficient** — the soundness lives in the **regenerated constraint** (`steps.cpp`/`poly_ext.rs`/`layout`), so route (ii) must revert those too and re-apply our assert-wrap, which likely touches *more* files than (i). Lean route (i) unless B2 finds otherwise. Pass **G1+G2**; re-validate the smoke harness runs and inspection/coverage tags still parse. **Treat the build + repro — not the "~1–2 h" estimate — as the gate.** **Also emit the build fingerprint (G10)** — risc0 HEAD SHA + `load_rs2`-present flag + instrumentation hash + guest image ID — so every later run can prove it used this exact vulnerable build.
- **A1.B3** — Deterministic MODE-1 repro: implement the minimal **coherent** read-divergence fault — a **propagating (during-execution) operand divergence** on the rs2-read of the `rs1==rs2` op, so the result is recomputed and **only** the missing same-register memory constraint is violated (a single post-execution read-cell edit alone trips the *present* local-compute constraint and does **not** suffice — see §2.3 / A3.B3 prediction). **Also characterize** which MODE-1 surface each variant's reg-mutation uses (during-exec propagating vs post-exec single-cell), since that determines per-variant findability. Produce the **G4 pre-fix-accepts / G5 post-fix-rejects** validation table; confirm it matches the B1 MODE-2 trigger.
**Status:** ✍️ **SPEC WRITTEN** — [`IV_POS_9_A1_VULN_BUILD_SPEC.md`](./IV_POS_9_A1_VULN_BUILD_SPEC.md); batch kickoffs drafted ([`composer/IV_POS_9_A1_BATCH1_KICKOFF.md`](./composer/IV_POS_9_A1_BATCH1_KICKOFF.md), [B2](./composer/IV_POS_9_A1_BATCH2_KICKOFF.md), [B3](./composer/IV_POS_9_A1_BATCH3_KICKOFF.md)). **Gate:** nothing downstream starts until **G1–G5 + G9** pass (the deterministic repro).

### Step A2 — Race harness: bug guests + targeted mutation + dual oracle + variant wiring
**Spec (to write):** `IV_POS_9_A2_RACE_HARNESS_SPEC.md`
**Accomplishes:** the reusable harness that lets all four variants *compete* to find the bug, with fair, well-defined success. Deliverables: the **race guests** (Pro §3.2/§3.3 — built to match the A1 mechanism, honoring L3): **Race-guest A** (minimal microbenchmark, inline-asm `remu`, reference compare, OOPS/SUCCESS, sizes S) and **Race-guest B** (contextual product-program with decoys, sizes M and optionally L); the **targeted bug mutation** (so the bug-relevant op/field is a *selectable arm* for every scheduler — L2/§2.4); and the **two oracles** (L4): strong journal-compare (capture+compare the `Receipt Decoder` output vs reference) and internal trace-soundness replay (extend `propagation_triage` toward reg/mem-value replay).
**Batches (outline):**
- **A2.B1** — Race-guest A (S) + host input ABI; verify it forces a real `remu`/`divu` **encoding `rs1==rs2`** (**G3**: disassemble the ELF to confirm identical register fields survived compilation) and that the A1 read-divergence fault flips the committed outcome.
- **A2.B2** — Race-guest B (M) product-program with decoys (and a size knob for L).
- **A2.B3** — Targeted **read-divergence** mutation (edit one of the two same-register read-value cells; **G6**: confirm it changes the result, not a no-op) + arm-space registration (**G7**: the bug-op/field is a reachable/selectable arm for V5/V6_uniform/V6_cTS/Hybrid, with per-variant selection-rate logging; reward never keys on acceptance — L10).
- **A2.B4** — Dual-oracle implementation: strong journal oracle (capture + reference compare); internal trace-soundness oracle (reg/mem replay); both with pre-fix/post-fix gating and a positive control.
**Status:** SPEC TODO. **Blocks on A1.**

### Step A3 — The race campaign + metrics + analysis
**Spec (to write):** `IV_POS_9_A3_RACE_CAMPAIGN_SPEC.md`
**Accomplishes:** run the staged race (L9), compute the bug-finding metrics (L6), and produce the Pro-/thesis-facing race report. Includes the **MODE-2 Arguzz baseline** as the external reference point.
**Batches (outline):**
- **A3.B1** — Dispatch plumbing for the race (manifest generator + run-id convention parameterized for *bug-commit host* + *bug guest*; reuse `chain_dispatcher`), and the MODE-2 Arguzz baseline run. **Every dispatched run asserts the VULNERABLE build fingerprint + the intended guest image ID before launch and records both in its DB (G11/G13); a patched-build or wrong-guest binary aborts the run.**
- **A3.B2** — Stage-1 smoke race (4 variants, 3 seeds, N=2000, guests S+M) → confirm at least V6_uniform/V6_cTS rediscover the bug; then Stage-2 thesis race (4 variants, ≥10 paired seeds, N=5000, **stop-on-first-confirmed-bug**, extend censored→N=10000); Stage-3 (20 seeds) if compute allows.
- **A3.B3** — Analysis + report: Kaplan-Meier time-to-first-confirmed-bug (**G8** confirmed-bug definition is the success criterion), find-rate table, the `P(find)=P(select)·P(apply)·P(diverge)·P(accept)` decomposition (the per-variant selection-rate from G7 feeds `P(select)`), pre-fix-vs-post-fix validation table, both oracles reported (strong for the headline-vs-Arguzz, internal for A4 fairness). **Key prediction to test (corrected):** the exploit needs a *coherent* witness (`read_rs2` diverged **and** result recomputed to match) so that only the *missing* same-register memory constraint is violated while the *present* local-compute constraint holds. A **propagating during-execution** fault (Arguzz: V6_uniform/V6_cTS) produces this naturally → expected to find it. A **single-cell post-execution** A4 edit changes only one cell → trips the present local-compute constraint → likely **cannot** find it on the strong oracle. So the live question is **whether V5 (pure A4) finds it at all**, and **whether Hybrid's reg-mutation is the propagating (Arguzz) flavor or the single-cell (A4) flavor** — A1 must characterize this; a V5 negative is the expected "limits of post-execution single-cell mutation" result (Pro §3.8), not a failure.
**Status:** SPEC TODO. **Blocks on A2.**

---

## 4. TRACK B — Multi-guest coverage sweep (second) — *ProG_Report_5 §2, §5 Step 2*

**Goal:** answer the generalization question — *is the A4-local / Arguzz-global complementarity (and Case B) a stable architectural property, or a `sha2-host` artifact?* — by re-running the four variants on a **focused suite** of structurally distinct guests.

> **Build context (important):** Track B runs on the **current patched tree** (`28e53771` / base `ebd64e43`) — it needs **no** back-port (the vulnerable commit is a Track-A-only concern). All Track-B guests therefore share one commit, so **cross-guest coverage IS comparable** (same circuit/EQZ universe); only *across-commit* comparison is forbidden (§2.4). Per-guest the executed-instruction mix differs, so the cross-guest aggregation normalizes within guest (rank / %-of-guest-universe), as L7 specifies. *(This is locked as **L13**; gate **G12** enforces it per run — every sweep run asserts the patched fingerprint and that the bug does not reproduce, so a sweep can never silently run the vulnerable binary.)*

**Three specs. B1 (harness) and B2 (guests + classifier) can pipeline; B3 (campaign) needs both.**

> **⚙️ EXECUTION UPDATE (2026-06-23) — Steps B1 + B2 are DONE; the spec files were CONSOLIDATED.** During execution, Step B1 (harness/dispatch) + Step B2 (guest suite) were delivered in ONE spec — **`IV_POS_9_B1_MULTIGUEST_FOUNDATION_SPEC.md`** (foundation: isolation + dispatch param + all 4 guests built & family-verified). The planned per-step spec files (`B1_GUEST_HARNESS`, `B2_GUEST_SUITE`) were NOT written separately. **Step B3 (sweep campaign)** is **`IV_POS_9_B3_SWEEP_CAMPAIGN_SPEC.md`** — spec written, execution NEXT. Two residuals carried forward (below): cross-guest aggregation (planned B1.B3) → folded into B3.4 analysis; the zone-classifier MRET/halt extension (B2.B1) → NOT done (non-blocking; needed for fine zone attribution in B3.4).

### Step B1 — Guest-aware harness: dispatch + analysis parameterization + cross-guest aggregation
**Spec (to write):** `IV_POS_9_B1_GUEST_HARNESS_SPEC.md`
**Accomplishes:** turn the single-guest pipeline into a **multi-guest** one. Deliverables: a **guest-id concept** threaded through build/bundle, manifest generation, run-id naming, and DB discovery; analysis (`build_d2_artifacts.py`, `d2h_lib.py`, `territory.py`) parameterized by guest (paths, host, host_args, signature loc-sets); and a **cross-guest aggregation layer** producing the per-guest tables + the cross-guest rank/coverage heatmap + rank-stability table (L7).
**Batches (outline):**
- **B1.B1** — Dispatch parameterization: `generate_*_manifests` driven by a per-guest descriptor (host bundle, guest_args, slug); run-id/dir convention includes `guest_id`; `discover.py` updated. **Every dispatched run asserts the PATCHED build fingerprint and that the bug does NOT reproduce (G12), plus the intended guest image ID (G13), recorded in its DB; a vulnerable-build binary in a sweep run is a hard failure.**
- **B1.B2** — Analysis parameterization: de-hardcode prod dirs/run names/host_args; make `V5_ECALL_MRET_SIGNATURE` and single-guest narrative constants guest-parameterized.
- **B1.B3** — Cross-guest aggregation: per-guest two-panel curves + summary table (Pro §2.3 metric list), cross-guest heatmap (guests × variants, local + CGC panels), rank-stability table.
**Status:** ✅ **DONE (consolidated into `IV_POS_9_B1_MULTIGUEST_FOUNDATION_SPEC.md`).** B1.B1 dispatch param = the Track-B `generate_sweep_manifests.py` (guest descriptor, guest-slug run-ids, per-job fingerprint guard G11 + audit sidecar); plus the physical **isolation** layer (worktree + read-only archives + the `a4/` code-isolation rule) — not in the original plan but required. B1.B2 analysis param + **B1.B3 cross-guest aggregation → folded into B3.4** (the sweep spec) since they consume sweep output.

### Step B2 — Guest suite authoring + zone/inspector extension
**Spec (to write):** `IV_POS_9_B2_GUEST_SUITE_SPEC.md`
**Accomplishes:** the **focused guest suite** (L8) and the classifier work that makes the priority guest's results trustworthy. Deliverables: the **ECALL/MRET/paging zone-classifier extension** (decode the instruction word from `--trace` and/or add `A4_INSPECT` tags so `pre_mret`/`post_mret`/`pre_halt`/`post_halt` and paging cycles get classified — closing the §2.2 gap); and three new guests + host ABIs: **Guest-1 ECALL/control-heavy** (the priority — V5's signature terrain), **Guest-2 memory-stress+branch/control**, **Guest-3 accelerator/Poseidon/BigInt** (activates dead `inst_p2`/`inst_bigint`/paging families). Stock-SHA optional.
**Batches (outline):**
- **B2.B1** — Zone-classifier/inspector extension (MRET/halt/paging) + unit tests + re-validation on the baseline guest (must not regress existing zones).
- **B2.B2** — Guest-1 (ECALL/control) + host ABI + inspection sanity (confirm the new zones populate).
- **B2.B3** — Guest-2 (memory-stress+branch).
- **B2.B4** — Guest-3 (accelerator/Poseidon/BigInt); confirm previously-dead families/zones activate.
- *(B2.B5 — optional mega-guest for the §6 appendix; not a thesis pillar.)*
**Status:** ✅ **GUESTS DONE (consolidated into the foundation spec, batch B1.4) + family-verified:** Guest-1 `g1_ecall_control` (control-dominated: 25k steps, 3572 branches + 2262 JalR), Guest-2 `g2_mem_stress` (3528 load/store + data-dep addressing), Guest-3 `g3_accelerator` (accelerated SHA = +34 `sys_sha` Eany + 128 div/rem). All built read-only, fingerprinted, distinct guest_image_ids. ⚠️ **RESIDUAL — B2.B1 zone-classifier MRET/halt extension NOT done** (non-blocking: MRET/halt cycles currently fall into default zones; the guests run + their families activate; the extension is needed only for *fine zone-level* territory attribution in B3.4 — do it before drawing zone-level conclusions). *(Self-review caught + fixed a Guest-1 dud — v1 ≈ baseline because risc0 batches env I/O; redesigned control-dominated.)*

### Step B3 — Staged sweep campaign + per/cross-guest analysis
**Spec (to write):** `IV_POS_9_B3_SWEEP_CAMPAIGN_SPEC.md`
**Accomplishes:** run the staged sweep (L9) and deliver the generalization verdict. Deliverables: **Stage-1 screening** (baseline + 3 new guests × 4 variants × 3 seeds × N=5000); pick the **2 most informative** guests; **Stage-2 thesis** (10 seeds × N=10000); the per-guest curves/tables, cross-guest heatmap, rank-stability, and the answer to "is the local/global split stable."
**Batches (outline):**
- **B3.B1** — Stage-1 screening dispatch (all guests/variants/seeds) + per-guest artifact build.
- **B3.B2** — Screening analysis + guest down-selection (which 2 guests are most diagnostic).
- **B3.B3** — Stage-2 thesis runs on the 2 selected guests + final cross-guest report (stability verdict).
**Status:** ✍️ **SPEC WRITTEN** (`IV_POS_9_B3_SWEEP_CAMPAIGN_SPEC.md`, batches B3.1–B3.4). **B1+B2 prerequisites DONE → execution UNBLOCKED.** **G0-reuse optimization (Ivan, adopted):** the screening reuses the D2.H N=10000 G0 campaign truncated to N=5000 (valid: G0 circuit/guest unchanged + N-independent ConstantFloor scheduling) → only the **3 new guests** run at screening (**36 jobs, ~135 run-hrs**, not 48/~180). Gated on the B1.3 G0 reuse-validation cross-check. **Folds in B1.B3 cross-guest aggregation (B3.4) + needs the B2.B1 zone-ext residual for zone-level analysis.** Compute coordinated with Track A (single shared box).

---

## 5. Sequencing & decision gates

```
A1 (vuln build + repro)  ──►  A2 (race harness)  ──►  A3 (race campaign + report)        [Track A — FIRST]
                                                              │
                                                              ▼  decision gate (§5.1)
B1 (harness) ─┐
              ├──►  B3 (sweep campaign + report)                                          [Track B — SECOND]
B2 (guests) ──┘
```

- **A1 is the universal gate.** If the deterministic repro fails at `98387806` (or the Zirgen dep is already patched), A1.B3 selects the nearest genuinely-vulnerable commit before A2/A3 proceed.
- **Track B can begin design (B1/B2 specs) in parallel with Track A's *runs*** (B1/B2 are mostly independent infra/guest work), but **Track B's campaign (B3) runs after Track A's race**, per L1.

### 5.1 Decision gate after the race (A3) — what the race result implies
| Race outcome | Read | Next move |
|---|---|---|
| **Arguzz/V6 finds it; Hybrid also finds it ≈ as fast** | Coverage breadth *does* translate to bug-finding | Strong thesis result; proceed to sweep; no V6-cTS-lite needed for this claim |
| **V6_cTS noticeably slower than V6_uniform** (over-concentrates on `INSTR_WORD_MOD`) | Feedback hurts on the bug-op surface | Trigger **V6-cTS-lite** (§6) on the most diagnostic guest before the sweep's scheduler claims |
| **A4/V5 cannot find it (strong oracle) but does on the internal oracle** | A4 exposes constraint weakness without app-level OOPS | Report both oracles (L4); frame as "limits of post-execution single-cell mutation," not a failure |
| **No variant finds it within budget** | Guest too hard / mutation not reaching the op / wrong commit | Revisit A1 mechanism + A2 arm reachability (§2.4) before declaring a negative |

The multi-guest sweep then tests whether the local/global complementarity + Case B hold across guests (the generalization claim), independent of the race.

---

## 6. Briefly noted — out of scope for detailed planning now (per Ivan)

These are acknowledged but **not** designed in this master; they are contingent follow-ups.

- **V6-cTS-lite** (`ProG_Report_5` §4.2) — collapse the Arguzz arm key (`kind × coarse_opcode_class` + boundary/core zone only) to test whether Case B was arm-geometry, not feedback. **Conditional and after** the race (or if the race shows V6_cTS badly underperforming). Future spec `IV_POS_9_V6CTS_LITE_SPEC.md`.
- **D1.E reward-rewire (V5-only)** (`ProG_Report_5` §4.3) — **not next critical path.** Run later only if the race/sweep show reward saturation or persistent A4-local-depth misses. Existing draft [`../cloud2/IV_POS_8_D1_E_SPEC.md`](../cloud2/IV_POS_8_D1_E_SPEC.md).
- **Mega-guest** (`ProG_Report_5` §2.5) — appendix/robustness stress test only (does Hybrid still avoid dilution; does V6-cTS over-concentrate); **not** the primary generalization experiment. Optional batch B2.B5.
- **Architecture carry-forward** (L11) — Hybrid_cTS (breadth) + V5_control (local-depth companion, run in parallel for bug-hunting) + V6_uniform (Arguzz baseline) + V6_cTS (ablation). Do not retire V5.
- **Repair / Mode-B / D3** — unchanged: deferred until there are real `propagated_candidate`s to isolate.

---

## 7. Spec & batch index (master tracking table)

| Track | Step | Spec (to write) | Accomplishes | Batches (outline) | Status |
|---|---|---|---|---|---|
| **A** | A1 | [`IV_POS_9_A1_VULN_BUILD_SPEC.md`](./IV_POS_9_A1_VULN_BUILD_SPEC.md) ✍️ written | Vulnerable build + commit validation + deterministic repro (resolves §2.3) | B1 MODE-2 existence proof + canonical trigger · B2 back-port + rebuild + fingerprint · B3 deterministic coherent repro + variant propagation — **all 3 kickoffs drafted** | ✍️ SPEC+BATCHES DRAFTED (gate) |
| **A** | A2 | `IV_POS_9_A2_RACE_HARNESS_SPEC.md` | Bug guests + targeted mutation + dual oracle + variant wiring | B1 guest A (S) · B2 guest B (M/L) · B3 targeted mutation + arm registration · B4 strong+internal oracles | ⛔ TODO (blocks on A1) |
| **A** | A3 | `IV_POS_9_A3_RACE_CAMPAIGN_SPEC.md` | Staged race + bug-finding metrics + report | B1 dispatch + MODE-2 baseline · B2 staged race (smoke→thesis→opt) · B3 KM/find-rate/decomposition + report | ⛔ TODO (blocks on A2) |
| **B** | B1+B2 | [`IV_POS_9_B1_MULTIGUEST_FOUNDATION_SPEC.md`](./IV_POS_9_B1_MULTIGUEST_FOUNDATION_SPEC.md) ✅ | **CONSOLIDATED** harness/dispatch (Step B1) + guest suite (Step B2) + isolation | B1.1 isolation+guard · B1.2 guest-aware generator · B1.3 G0 equiv smoke · B1.4 **4 guests built+verified** | ✅ **DONE** (zone-ext residual; cross-guest aggregation → B3.4) |
| **B** | B3 | [`IV_POS_9_B3_SWEEP_CAMPAIGN_SPEC.md`](./IV_POS_9_B3_SWEEP_CAMPAIGN_SPEC.md) ✍️ | Staged screening → thesis + per/cross-guest analysis | B3.1 screening (**3 new guests; G0 reused-truncated**) · B3.2 down-select · B3.3 thesis · B3.4 cross-guest analysis | ✍️ **SPEC WRITTEN — execution NEXT** (unblocked) |
| **A** | AP | [`IV_POS_9_AP_PLANTED_ISREAD_SPEC.md`](./IV_POS_9_AP_PLANTED_ISREAD_SPEC.md) | **Planted A4-findable bug** (remove `IsRead` on ReadReg). **B1/B2 attempted via zirgen-regen → FAILED (plumbing path-doubling + df6fb9d drift, ~2 days circling, science untested). Pivoting to the surgical patch of the committed circuit (spec §2.2 PRIMARY).** See spec CURRENT STATUS block. | B1 build `bench-isread` (surgical) + hardened GP1 + mutated-V0 · B2 (0,1,0) corpus + bracket · B3 live A4+Arguzz | 🔧 BLOCKED→PIVOTING (surgical patch) |
| — | (cond.) | `IV_POS_9_V6CTS_LITE_SPEC.md` | Arm-space ablation | TBD | 💤 conditional/after race |
| — | (defer) | `../cloud2/IV_POS_8_D1_E_SPEC.md` | V5 reward-rewire causal test | B0–B4 (existing draft) | 💤 deferred |

Legend: ⛔ spec to write · 💤 deferred/conditional.

**Governing context:** [`ProG_Report_5.md`](./ProG_Report_5.md) (requirements) · [`../cloud2/IV_POS_8_BACKPORT_SCOPING.md`](../cloud2/IV_POS_8_BACKPORT_SCOPING.md) (Track-A starting point — guest shape correct; mutation framing corrected per the now-resolved §2.3) · [`../cloud2/IV_POS_8_D2_B_MECHANISM_REPORT.md`](../cloud2/IV_POS_8_D2_B_MECHANISM_REPORT.md) (dead families/kinds for Track B) · [`../cloud2/IV_POS_8_PRO_CHECKIN.md`](../cloud2/IV_POS_8_PRO_CHECKIN.md) (the checkpoint these tracks build on).

---

## 8. Open items for Ivan (before spec authoring)

1. **Confirm the two-track scope + spec breakdown** (A1–A3, B1–B3) and that everything else stays in §6.
2. **A1 mechanism (the former §2.3 conflict) — RESOLVED FROM SOURCE.** The bug is the same-register (`rs1==rs2`) double-read divergence (GPT correct, ProG's mechanism wrong); guest encodes `rs1==rs2`, fault = read-divergence; `98387806` is source-level vulnerable. See [`BUG_MECHANISM_VERIFIED.md`](./BUG_MECHANISM_VERIFIED.md). A1's MODE-2 repro is now a **confirmation gate (G1–G5,G9)**, not an open investigation. *Confirm you accept this resolution* (no longer "resolve on paper vs empirically" — it's decided by the #3181 diff).
3. **Spec authoring order:** I propose authoring `IV_POS_9_A1_VULN_BUILD_SPEC.md` first (it gates everything), then A2/A3; B1/B2 specs can be drafted in parallel once A1 is underway.
4. **Commit fallback policy (L5):** if `98387806` (or its Zirgen dep) proves already-patched, who chooses the fallback commit — and is the completeness bug (`4c65c85a`, a separate larger back-port) explicitly out of scope? (I assume yes.)
5. **Guest-authoring ownership:** the focused guests (B2) are hand-written Rust + host ABI; confirm whether to hand-craft them or lean on the MODE-2 CircIL generator to emit them.
6. **Binary/guest provenance (L13/L14 + G10–G13) — NEW, per your explicit ask.** Confirm: (a) the **commit assignment** — vulnerable `98387806` is **race-only**, the patched tree is **sweep + all coverage** (ProG_Report_5 assigns the vulnerable commit only to the race, never to the sweep — this discipline is our addition, not Pro's); (b) that **every smoke/POS run must assert + record its build fingerprint and guest image ID before we trust any result**, with the symmetric G12 ensuring a sweep can never run the vulnerable binary. *Open implementation question for the A1/B1 specs: where the fingerprint is stamped (build-time stamp file vs a host `--version` emit vs an `A4_INSPECT` tag) and how the dispatcher reads it before launch.*

*This master is updated as specs are written/locked and batches land. Each spec, when created, links back here; each batch links to its spec.*
