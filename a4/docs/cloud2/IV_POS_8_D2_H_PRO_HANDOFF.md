# IV.POS.8 — D2.H Results + Next-Phase (Bug-Finding) Hand-off to Pro

**To:** ChatGPT Pro · **From:** Ivan · **Date:** 2026-06-21
**Prior context you (Pro) wrote:** `ProG_Report_3.md`; my last check-in was `IV_POS_8_PRO_CHECKIN.md`. This doc uses that nomenclature.

> **READER NOTE (internal):** This file has **two parts**.
> **PART 1 is Pro-facing** — it presents the completed D2.H results and asks for your steer on the next phase.
> **PART 2 is an internal appendix** (my own investigation notes answering specific questions) that **will be deleted before this is sent to Pro.** It is included here only so the reasoning lives in one place.

---
---

# PART 1 — PRO-FACING

## 0. What this is and what I need from you

Two things:

1. **I'm presenting completed results** — the full 4-variant constraint-space-exploration study (D2.H), now run on the **complete campaign** (4 variants × 3 seeds × N=10000 = 12 runs). Report + notebook are attached (§5).
2. **I need your architecture call on the next phase.** I have **~1 week** to focus on results for these 4 variants, and I want to pivot from *coverage* to *bug-finding*. My bosses' specific question is: **how do my variants compare at finding the soundness bug Arguzz originally found in RISC Zero — faster, slower, or not at all?** I need your steer on how to set that campaign up before I spend the week on it.

You have no repo access, so §1 is a self-contained primer, §2 the D2.H findings, §3 the next-phase problem statement + the specific decisions I need from you.

---

## 1. Primer (self-contained — you have no repo access)

### 1.1 The two surfaces and the four variants (unchanged from last check-in)
- **A4** (my framework) = **post-execution** trace-cell mutation: the guest runs once, the prover records a preflight trace, A4 mutates one trace field before witgen, and we see whether a constraint rejects.
- **Arguzz** (prior paper, arXiv 2509.10819) = **during-execution** fault injection: perturb a register/memory/PC value mid-execution and let the VM propagate it. **Arguzz ≡ V6-uniform** in my naming.

| Variant | Surface | Scheduler | Kinds |
|---|---|---|---|
| **V5_control** | A4 trace-cell | constrained-TS | 11 A4 |
| **V6_uniform** (=Arguzz) | exec-fault | round-robin | 11 Arguzz |
| **V6_cTS** | exec-fault | constrained-TS | 11 Arguzz (same set as V6_uniform → isolates scheduler) |
| **Hybrid_cTS** | both | constrained-TS | 11 A4 + 4 Arguzz (15) |

### 1.2 Two coverage dimensions
- **Local coverage** = distinct per-row `.zir` `EQZ` constraints tripped (`constraint_loc`).
- **CGC coverage** = distinct global cross-row permutation/lookup residues perturbed (`compressed_global_coverage`).
An underconstraint (a soundness bug) can live in either; they're orthogonal.

### 1.3 Two operating modes (this distinction is central to the next phase)
- **MODE 1 — "exploration"** (everything in D2.H): one **fixed** guest program, run for N=10000 "mutations," measuring coverage. All four variants live here.
- **MODE 2 — "bug-finding"** (the original Arguzz): **generate a random guest program each iteration**, inject a fault, and check whether the verifier wrongly accepts. This is how Arguzz found its RISC Zero bugs. My four variants do **not** run in this mode today.

---

## 2. D2.H results (completed — full campaign, all 3 seeds)

**Headline: the architectures are complementary along a local-vs-global axis, and the data inverts the thesis's prior prediction.**

| variant | local locs (of 52-union) | CGC contexts | CGC per local loc |
|---|---:|---:|---:|
| V5_control (A4) | **49** | 449 | 9.2 |
| V6_uniform | 37 | 565 | 15.3 |
| V6_cTS | 36 | **670** | **18.6** |
| Hybrid_cTS | **49** | 591 | 12.1 |

- **A4 owns local** (49 of 52 locs; pure-Arguzz 36–37). **Arguzz owns global** (V6_cTS 670 CGC; A4 the *fewest*, 449).
- **Thesis inversion (F26):** my thesis predicted A4's post-execution mutations would reach the *global* structures and Arguzz's during-execution faults the *local* ones. **The data says the opposite** — per local loc, Arguzz reaches ~2× more global structure than A4. **This is confound-proof:** even V6_uniform (no bandit, so no arm-weighting artifact) beats A4 on CGC (565 vs 449), and the D2.G paired test shows V5 at **−116 CGC vs V6_uniform**.
- **Hybrid is the broad unifier** — best local (49) + second-best global (591) — supporting the Hybrid hypothesis on coverage grounds.
- **Crucial caveat: 0 confirmed soundness candidates** in the whole campaign. D2.H measures *coverage of the search space*, not realized bugs. **This is exactly why the next phase must be bug-finding, not more coverage.**

Full detail, intuitive explanations, and the exact-number appendix are in the attached report (§5).

---

## 3. The next phase — what I need you to design with me

### 3.1 The goal (my bosses' question)
**For the soundness bug Arguzz found in RISC Zero, can my variants (V5/V6/Hybrid) find it, and how fast relative to Arguzz?** I must rerun **V6_uniform (=Arguzz)** and **Hybrid_cTS** for sure; **V6_cTS** is optional. I want a clean, paper-ready comparison.

### 3.2 The bug (fully identified)
- **CVE-2025-52484 / GHSA-g3qg-6746-3mg9 / risc0 PR #3181 (ZKVM-1392) + zirgen PR #238 (ZIR-366).** **Critical soundness.**
- **Root cause:** a missing constraint in the rv32im circuit for **3-register instructions when both source registers are the same (rs1 == rs2)** — e.g. `remu rd, x5, x5`. The circuit did two register reads of the same address in the same cycle without constraining them equal, so a malicious prover could give the two reads **different** values → forge a false `remu`/`divu` result. (My thesis already documents the discovery: "Arguzz injected a fault into an unsigned remainder instruction so that one operand was replaced… a constraint distinguishing the first and second source registers was missing.")
- **Triggering mutation:** `PRE_EXEC_REG_MOD` on a source-register read of a 3-register op with rs1==rs2.
- **Circuit families involved:** `inst_div` / `inst_mul` (the DivU/RemU "DIV0" instruction zone).

### 3.3 The two facts that shape the whole campaign
1. **I am NOT checked out at the vulnerable commit.** My tree has the fix. The bug lives at risc0 commit `98387806…` (2025-05-21); my A4 build sits **53 commits later** on a post-fix base (#3305, 2025-08-09). **To find the bug, the build must be moved back to the vulnerable commit** (details + cost in Part 2). The original Arguzz fuzzer already ships injection support for that exact commit; my A4 instrumentation does not (it would need a back-port).
2. **A coverage tension worth your eye.** D2.H shows the *vulnerable instruction family* (inst_div/inst_mul, 3-register) is reached by **A4 (V5/Hybrid)** but **not at all by pure-Arguzz (V6=0 locs)** on my current guest — yet **Arguzz is what historically found the bug**, because in MODE 2 its random generation produced the `rs1==rs2` instruction that my fixed guest lacks. So "who covers the family on the current guest" may **not** predict "who finds the bug," because bug-finding depends on the *guest* containing the vulnerable pattern.

### 3.4 The design fork I need you to weigh in on
**Approach A — MODE 1, bug-targeted fixed guest, all variants:** craft a guest containing `remu/divu rd, rsX, rsX` (same source register), rebuild against the vulnerable commit, and run **all four variants** with the *same* guest, varying only the variant. Clean apples-to-apples; directly answers "faster/slower/can't." Cost: back-porting my A4 instrumentation to the vulnerable commit — **I verified this is small (~1–2 h code transplant: 49/60 files apply byte-clean, residue is one regex + 3 tiny merges; see `IV_POS_8_BACKPORT_SCOPING.md`).** So the real cost is rebuild + validation + the run, not the port.
**Approach B — MODE 2, original Arguzz random-gen at the vulnerable commit:** runs out-of-the-box for V6_uniform (=Arguzz), but my A4/Hybrid/cTS variants don't exist in MODE 2 (would need porting), and random generation makes the per-variant comparison noisier.
**Approach C — hybrid of the two:** B to re-confirm Arguzz finds it (sanity/Arguzz baseline), plus A for the controlled variant comparison.

### 3.5 The open knobs I specifically want your call on
1. **Mode:** A, B, or C? (My lean: C — but the controlled comparison in A is the deliverable.)
2. **Commit/port:** the A4 back-port to `98387806` is **verified cheap (~1–2 h, see scoping doc)**, so feasibility isn't the blocker. The question is whether the controlled MODE-1 comparison is worth doing at all vs. just running MODE-2 Arguzz — i.e. do you want the apples-to-apples variant table, or is "Arguzz finds it / does Hybrid?" enough?
3. **Guest:** craft a minimal `rs1==rs2` bug-targeting guest (small N suffices, the instruction is hit immediately), or run a broad/random guest (needs large N to stumble on the pattern)? How "obvious" should I make the bug — minimal repro, or buried in a realistic guest?
4. **Budget (N):** I have no documented "iterations-to-bug" for this bug anywhere (it's not in the repo and not in the paper). For a **bug-targeted** guest, what N gives a fair time-to-find comparison — and how should I define "time-to-find" (first accepted mutation that exploits the missing constraint)?
5. **Metric:** what's the right head-to-head metric — mutations-to-first-exploit, wall-clock-to-first-exploit, or probability-of-finding-within-budget across seeds? How many seeds for a credible claim?
6. **Multi-guest:** I also want to rerun the *exploration* study on new guests (IV.POS.9). Should the new guests be chosen to (a) activate currently-dead families (Poseidon `inst_p2`, BigInt) for the coverage story, (b) contain the bug pattern for the bug-finding story, or (c) both in one guest set? Which buys more for the thesis?

### 3.6 What I'm NOT asking
Not asking you to re-litigate the D2.H coverage findings (they're done). I'm asking how to convert the week into a **bug-finding** result my bosses can read.

---

## 4. My current lean (for you to push on)
- **Approach C.** Run MODE-2 Arguzz at `98387806` first as the existence proof + Arguzz baseline (cheap, ready). In parallel, back-port the A4 instrumentation to `98387806` and run **all four variants** in MODE 1 on a **minimal `rs1==rs2` bug-targeting guest** at small-to-moderate N (e.g. N=2000–5000), 3 seeds, metric = **mutations-to-first-exploit** + **find-rate-within-budget**.
- **Multi-guest:** a small guest *set* — one bug-targeted (`rs1==rs2`), one Poseidon-heavy (activates `inst_p2`), one BigInt — to serve both the bug story and the coverage story.
Tell me where this is wrong, what to cut to fit a week, and what single result would be most convincing.

---

## 5. Attached artifacts (Ivan attaches these alongside this doc)
| Artifact | Path | What it is |
|---|---|---|
| **D2.H report** | `a4/runs/iv_pos_8/d2g/D2H_REPORT.md` | The full exploration write-up (self-contained, intuitive) |
| **D2.H notebook (HTML)** | `a4/runs/iv_pos_8/d2g/d2h_exploration.html` | 3 figures: coverage curves, total-vs-exclusive territory, per-family heatmap |
| **D2.H spec** | `a4/docs/cloud2/IV_POS_8_D2_H_SPEC.md` | Why local+CGC are the right curves; build/validation log |
| **D2.G verdict** | `a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/d2g_case_verdict.md` | Case B (V6-cTS ties V6-uniform on territory; Hybrid wins); 0 soundness candidates |
| **Prior check-in** | `a4/docs/cloud2/IV_POS_8_PRO_CHECKIN.md` | Last steer request (variant definitions, integration) |

---
---

# PART 2 — INTERNAL APPENDIX (delete before sending to Pro)

*All of this is my own investigation answering the exact questions I asked. Verified against the repo on 2026-06-21 unless marked otherwise. "NOT IN REPO" = genuinely undocumented locally; "PAPER-ONLY" = likely only in the Arguzz paper.*

## A. The bug — exactly what Arguzz found (verified)
- **Identity:** CVE-2025-52484 = GHSA-g3qg-6746-3mg9 = risc0 #3181 (ZKVM-1392) = zirgen #238 (ZIR-366). Severity **Critical**.
- **Advisory text (verbatim, fetched):** "Due to a missing constraint in the rv32im circuit, any 3-register RISC-V instruction (including remu and divu)" could be exploited; the attack confuses "the RISC-V virtual machine into treating the value of the rs1 register as the same as the rs2 register due to a lack of constraints."
- **zirgen #238 title (verbatim):** "ZIR-366: Fix to remove extra register read when both source registers are the same"; commit message "Disallow memory IO to same address on same cycle." → registers are memory-mapped; reading the same register twice in one cycle = two memory reads of one address; the missing constraint failed to force those two reads equal.
- **Affected versions:** risc0-circuit-rv32im ≥2.0.0 <2.0.4 (fix 2.0.4); risc0-zkvm ≥2.0.0 <2.1.0 (fix 2.1.0).
- **My thesis already explains it** (`a4/docs/thesis.md:241`): Arguzz injected a fault into an **unsigned remainder (remu)** so one operand was replaced; rs1/rs2 indistinguishable → false statement accepted. Injection kind = **`PRE_EXEC_REG_MOD`** (thesis line 296).
- **Second RISC Zero bug** (#3015 / ZKVM-1260, "missing ControlDone cycle"): **completeness**, not soundness (wrong segment cycle count → crash). PR text suggests it came from a Hackenproof report, not necessarily Arguzz fuzzing. Vulnerable commit `4c65c85a…` (2025-03-24), **134 commits** behind my base. Lower priority for the bosses' soundness question; different oracle.

## B. Commit / checkout situation (verified by git)
From `projects/risc0-fuzzer/risc0_fuzzer/settings.py` (`RISC0_AVAILABLE_COMMITS_OR_BRANCHES`) and `git` in `workspace/risc0-modified`:

| label | commit | date | note |
|---|---|---|---|
| **current base** | `ebd64e43` (#3305) | 2025-08-09 | what my A4 build (`28e53771`) sits on |
| soundness **fix** | `67f2d81c` (#3181) | 2025-05-23 | **ancestor of my base** → my tree is patched |
| soundness **bug** | `98387806` | 2025-05-21 | last good state *before* the fix; **53 commits behind base** |
| completeness fix | `31f65701` (#3015) | 2025-03-25 | also in my base |
| completeness bug | `4c65c85a` | 2025-03-24 | 134 commits behind base |

- **Confirmed:** `git merge-base --is-ancestor 67f2d81 ebd64e43` → **YES**. My current checkout **has the soundness fix** → none of my 4 variants can find the bug as-is; the bug isn't in the tree.
- **To make it findable:** move the RISC Zero build to `98387806`.
  - **MODE 2 (original Arguzz) is already set up for it:** `projects/risc0-fuzzer/risc0_fuzzer/zkvm_repository/injection_sources/rv32im_rs_9838780.py` (43 KB modified `rv32im.rs` for commit `9838780`) exists, alongside `…_67f2d81.py` (fix) and `…_4c65c85.py` (completeness bug). So MODE 2 can fuzz the vulnerable commit out-of-the-box.
  - **MODE 1 (my A4/Hybrid/cTS) needs a back-port — but it is small (verified, see `IV_POS_8_BACKPORT_SCOPING.md`).** I tested it mechanically by applying our instrumentation diff onto a throwaway worktree at `98387806`: **49 of 60 touched files apply byte-identically**, 2 more 3-way auto-merge, and the residue is **one mechanical regex** (`steps.cpp`: re-wrap ~125 `assert` sites) + **3 tiny Rust hand-merges (1 conflict-hunk each)** + lockfile regeneration. The heavy C++ coverage hooks (`ffi.cpp`, `witgen.h`, `eval_check.cpp`) apply clean, and constraint-coverage transfers for free (the bug commit's native `steps.cpp` already has 1868 `EQZ()` calls our byte-clean `witgen.h` instruments). **Code transplant ≈ 1–2 hours**; toolchain already matches (1.85.0). So the back-port is *not* the gating cost of Approach A — rebuild + validation + the campaign are. This de-risks Approach A considerably.

## C. MODE 1 vs MODE 2 — structural map (from sub-agent investigation)
- **MODE 1 (a4/):** fixed guest (`workspace/output/methods/guest`, a CircIL-generated circuit with `%`/remu + inline asm, loaded as a compile-time-embedded ELF in `risc0-host`). A "mutation" = one fault on the **fixed** recorded execution; N=10000 in the manifest (`a4/pos/manifests/iv_pos_8/d2f_production.chain`). Variants defined in `a4/standalone/variants.py`; bandit in `a4/standalone/bandit_ts.py`; V6_uniform has its own driver `a4/standalone/v6_uniform_driver.py`. **Guest is compile-time, not runtime-pluggable** — swapping guests = edit `methods/guest/src/main.rs` + host `Args` + `cargo build` + re-bundle.
- **MODE 2 (projects/risc0-fuzzer/):** loop in `libs/zkvm-fuzzer-utils/zkvm_fuzzer_utils/fuzzer.py:206-282` — generate random project (CircIL, `libs/circil`), build, execute, inject. Runs to timeout (`TIMEOUT_PER_RUN=4min`), not a fixed N. Single fuzzer, no V5/V6/Hybrid variant concept.
- **Can the 4 variants run in MODE 2?** Not today — they assume a fixed guest's pre-computed inspection/zone/arm-universe (`a4/standalone/semantic_arm_universe.py`). Porting = move inspection + arm-universe setup *inside* a per-program loop. Non-trivial. **Reusable across modes:** the executor (`a4/core/executor.py`), the mutation-config JSON schema, the Arguzz fault bridge (`a4/standalone/mutations/arguzz_bridge.py`), the coverage DB.
- **Key implication:** "rerun Arguzz" most faithfully = MODE 2 at `98387806` (ready). The controlled variant comparison the bosses want is cleanest in MODE 1 on a shared bug-targeted guest (needs the back-port).

## D. Can a *fixed* guest trigger the bug? (the crux for Approach A)
- The bug needs a 3-register op with **rs1==rs2**. My current guest has `var1 % var5` and `const % var23` — **different** source registers → does **not** trigger it.
- **Fix:** craft a guest with inline asm `remu rd, x5, x5` (or `divu`). The README confirms Arguzz uses inline-assembly generation (and a `--no-inline-assembly` flag), which is how MODE 2 produces `rs1==rs2` patterns my fixed guest lacks. Crafting a minimal bug guest is straightforward (edit `methods/guest/src/main.rs`, add an `asm!` block, rebuild).
- **Which variants should trigger it (hypothesis, to be tested — this is the experiment):**
  - **V6_uniform / V6_cTS:** `PRE_EXEC_REG_MOD` during execution = the original discovery path → expected to find it.
  - **V5 (A4):** has a post-execution `PRE_EXEC_REG_MOD` equivalent; whether mutating the recorded read-cell exposes the missing same-address constraint is **the open question** — plausibly yes, but unconfirmed.
  - **Hybrid:** has both → should find it if either parent can.
  - The bosses' "faster/slower/can't" is precisely this matrix.

## E. Scale / budget — what's known vs not
- **Verified throughput** (`a4/docs/precloud/txt/Results_from_Campaigns.txt`): ~**2.87 s/mutation** on AMD EPYC 9354 (32-core); N=6000 ≈ **5 h/run**, N=10000 ≈ **8 h/run**. (Matches my own measured 5.5–9.2 h/run for the D2.H campaign.)
- **Coverage convergence** (same doc, older IV.POS.5 guest, 46-constraint universe): the productive strategy covered the universe within ~N=2000; the rare "Input" constraints appeared in the 1000–1900 range.
- **NOT IN REPO:** the number of iterations / wall-clock Arguzz needed to find the actual risc0 soundness bug. No `findings.csv` with a saved seed/input for the risc0 bugs is committed (the `check` command + `CircuitChecker` exist in `projects/risc0-fuzzer/`, but no recorded RISC Zero finding to replay). No time-to-bug metric anywhere.
- **PAPER-ONLY (likely):** Arguzz's original time/iterations-to-bug on RISC Zero — and even the paper may only give aggregate fuzzing time, not per-bug. **Implication:** for the budget question I should *measure* time-to-find myself on a bug-targeted guest rather than try to match an unknown historical number.

## F. Guests available for multi-guest (IV.POS.9)
- **risc0 examples in the submodule** (`workspace/risc0-modified/examples/`): `sha`, `keccak`, `ecdsa`, `bn254`, `bls12_381` (Poseidon-heavy), `digital-signature`, `json`, `chess`, `xgboost`, etc.
- **For the coverage story:** a Poseidon-heavy guest activates `inst_p2` (sparse today); a BigInt guest activates `inst_bigint` (absent today); a paging-heavy guest may activate the 5 currently-dead A4 cycle/paging kinds (NFP-11).
- **For the bug story:** a hand-crafted `rs1==rs2` guest (above).
- Swapping any guest = rebuild host + re-bundle (compile-time embed). Cheap mechanically; the cost is the rebuild + redeploy, not code.

## G. Known / unknown / hidden / paper-only — ledger
| Question | Status | Source |
|---|---|---|
| What is the soundness bug? | **KNOWN** | advisory + zirgen#238 + thesis.md:241 |
| Which injection kind triggers it? | **KNOWN** (`PRE_EXEC_REG_MOD` on rs1==rs2 3-reg op) | thesis + advisory |
| Vulnerable commit? | **KNOWN** (`98387806`) | settings.py + git |
| Am I at the right commit? | **KNOWN: NO** (I'm patched, 53 commits ahead) | git merge-base |
| Is MODE 2 ready for the bug commit? | **KNOWN: YES** | injection_sources/rv32im_rs_9838780.py |
| Is MODE 1 (A4) ready for it? | **KNOWN: NO** (needs back-port) | submodule base = post-fix |
| Does my current guest trigger it? | **KNOWN: NO** (rs1≠rs2) | guest source |
| How many iterations did Arguzz need? | **NOT IN REPO** (likely PAPER-ONLY, maybe not even there) | sub-agent sweep |
| Can A4/V5 (post-exec) find this bug? | **UNKNOWN** — the experiment | — |
| Time-to-bug for my variants? | **UNKNOWN** — to be measured | — |

## H. Concrete recommended setup (my draft, pre-Pro)
1. **Back-port** A4 instrumentation to `98387806` (or get Pro's cheaper alternative). Build `risc0-host` at the vulnerable commit.
2. **Craft a minimal bug guest:** inline asm `remu x3, x5, x5` with x5 set from input, plus a few decoy instructions. Verify it executes.
3. **MODE-2 sanity run:** original Arguzz at `98387806` → confirm it re-finds the bug (existence proof + Arguzz baseline). This is ready now.
4. **MODE-1 controlled run:** all 4 variants on the bug guest at `98387806`, 3 seeds, N≈2000–5000. Metric = mutations-to-first-accepted-exploit + find-rate. The accept (proof verifies when it shouldn't) is the soundness signal — same oracle D2.G already uses (it currently reports 0 accepts on the patched tree; here we expect >0).
5. **Multi-guest coverage rerun (if time):** add a Poseidon guest + a BigInt guest to the D2.H exploration to fill the family blind spots.
6. **Deliverable:** a small table — variant × {finds it?, mutations-to-find, wall-clock} — plus the multi-guest coverage refresh.
