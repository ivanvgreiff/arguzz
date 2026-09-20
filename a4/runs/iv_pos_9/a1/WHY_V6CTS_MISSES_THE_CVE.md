# Why V6-cTS fails catastrophically at finding the rs1==rs2 CVE while V6-uniform succeeds

> **⚠ PARTLY SUPERSEDED (2026-06-27).** A later direct read of the run databases (all 6 seeds) found two facts
> this document did NOT account for, which change the *mechanism* (the headline result — uniform 9, cTS 0 — is
> unchanged and correct):
> 1. **V6_cTS's reward signal was identically ZERO in every seed** (all `mutation_rewards` rows = 0). The bandit
>    never learned; its adaptive tier sampled near-prior Beta posteriors and favored least-pulled arms. So the
>    "coverage-novelty reward saturates and *starves* the rare op" story below is **not** what happened — there
>    was no working reward to starve anything; cTS was effectively uniform-over-417-arms.
> 2. **The semantic zones were misaligned with the inject-step space:** the divide inject steps 444/449 are
>    classified into `core_memory_store`, and the `INSTR_WORD_MOD|core_div` arm injects at steps 441/436 (not
>    the divide). So §2–§4's "core_div hammering" framing is on the wrong arm.
> The corrected, data-grounded analysis is in **`PRO_SCHEDULER_DIAGNOSIS_PACKAGE.md` §5** (use that as the
> authority). Below is retained for history; treat its *mechanism* claims with the above caveats.

**Scope:** IV.POS.9 CVE race (rs1==rs2 underconstraint, CVE-2025-52484 / risc0 #3181), B2 vulnerable
build, guest = `remu a0,a1` + `divu a2,a3`. Replay-oracle confirmed (batches 1–3, 6 seeds). This doc
explains, in depth, the **scheduler** reason V6-cTS (and Hybrid) find **0** while V6-uniform finds **9**.

---

## 0. The result in one line
Both schedulers spend N=5000 mutations/seed and both touch ~2,200 distinct trace steps with near-identical
overall spread (top-10 steps = 15–18% of pulls for both). **The difference is *which* steps they hammer.**
V6-uniform pours **910 mutations each into the vulnerable `remu` (step 444) and `divu` (step 449)**;
V6-cTS pours **6 and 1**. That ~150× targeting gap on the vulnerable instruction — not coherence, not the
mutation surface — is the entire reason cTS finds nothing.

## 1. The numbers (replay-confirmed, 6 seeds, `--inject` step indexing)
| variant | total muts on remu(444) | total on divu(449) | **INSTR_WORD** on 444/449 | **CVE finds** |
|---|--:|--:|--:|--:|
| **V6_uniform** | **910** | **910** | **114 / 118** | **9** (3 remu + 6 divu) |
| V6_cTS | **6** | **1** | **2 / 0** | **0** |
| Hybrid_cTS | 5 | 1 | 1 / 0 | 0 |
| V5_control (A4) | 5 | 1 | 0 / 0 | 0 |

- Per-seed finds (uniform): seeds {1234:1, 1236:2, 1238:4, 1239:2}, seeds 1235/1237 = 0 → **found in 4/6
  seeds**, ~1.5/seed. Not a single lucky seed.
- **Empirical hit rate:** 9 finds / 232 INSTR_WORD attempts at the vuln steps ≈ **1/26** per attempt
  (consistent with the d=1 single-bit-flip rs2-alias rate ~1/30; the operands are a0/a1 and a2/a3, one
  Hamming bit apart, so `random_word` strategy-0 can alias in one flip).
- **Expected finds = (attempts) × (1/26):** uniform 232×(1/26) ≈ **9** ✓; cTS 2×(1/26) ≈ **0.08** → **0** ✓.
  cTS doesn't fail at *aliasing*; it fails at *getting enough attempts on the vulnerable instruction*.

## 2. The two schedulers (exact mechanisms)
### 2.1 V6-uniform = `ArguzzScheduler` (round-robin over instruction-kinds)
`v6_driver_v2.py:ArguzzScheduler.pick()`:
```python
min_count = min(self._counter.get(c, 0) for c in self._candidate_instrs)
prefs = [c for c in self._candidate_instrs if self._counter.get(c, 0) == min_count]   # least-used kinds
# -> pick a candidate INSTRUCTION-KIND with the minimum pull count, then a step + applicable mutation-kind
```
The **scheduling unit is the instruction-kind** (`remu`, `divu`, `add`, `beq`, …). It is strict
least-used-first → **every instruction-kind gets an equal share, independent of how rare that instruction
is in the trace.** `remu` occurs once in the guest, but as its own *kind* it receives a full `~1/n_kinds`
slice → ~910 mutations land on the single remu step. **Rarity is irrelevant; each instruction-kind is a
first-class citizen.**

### 2.2 V6-cTS = `ConstrainedTSScheduler` (coverage-bandit over (kind, zone) arms)
- **Arm = `(mutation_kind, semantic_zone)`** (`semantic_arm_universe.py`), e.g. `(INSTR_WORD_MOD,
  core_arithmetic)`. There are **~200–350 arms** for V6-cTS.
- Pick tiers (`bandit_ts.py`, IV_POS_8_D2_BERNOULLI_FLOOR_SPEC): (1) cold-start, (2) singleton, (3)
  **per-arm Bernoulli floor (fraction 0.55)**, (4) **adaptive Thompson sampling** — argmax of `Beta(α,β)`
  samples on a **coverage reward**.
- **After an arm is chosen, the STEP within it is picked UNIFORMLY** — `bandit_ts.py:287`:
  `step = steps[0] if len(steps)==1 else self.rng.choice(steps)`.

So a rare instruction like `remu` is **not** a scheduling unit — it is **one step inside a zone** that also
contains the x/y ALU ops and other arithmetic, and it competes for budget via the zone-arm's *coverage
reward*.

## 3. Root cause — three compounding penalties cTS imposes on the rare vulnerable instruction
### 3.1 Granularity: instruction-kind (uniform) vs (kind, zone) (cTS)
Uniform privileges rarity (remu = its own unit). cTS dilutes it: when the `(INSTR_WORD_MOD, <remu's
zone>)` arm is pulled, the **uniform within-arm step-pick** gives remu only `1/N_zone_steps`. A zone holds
many steps, so the rare remu gets a small fraction of an already-shared budget.

### 3.2 Reward: coverage novelty *saturates* for a 1-occurrence instruction
cTS's tier-4 (which spends most of the budget) is Thompson sampling on a **coverage-novelty reward**.
`remu`/`divu` occur **once** → their coverage is exhausted after the first hit → the arm's `Beta`
posterior collapses toward low reward → the adaptive tier **almost never re-selects** that arm. Uniform
has **no reward term at all** — its round-robin keeps selecting remu forever, oblivious to the fact that
it's "already covered." For a bug that needs ~26 *repeated* attempts *after* first contact, the
coverage-novelty signal points exactly the wrong way.

### 3.3 The floor is per-arm and far too thin to compensate
The Bernoulli floor (0.55) is shared across **~300 arms**: per-arm floor ≈ `0.55 × epoch(100) / 300 ≈
0.18` pulls/epoch → ~**9 floor-pulls per arm** over N=5000. That ~9 is for the whole `(kind, zone)` arm,
then **further divided by `N_zone_steps`** for remu specifically → roughly **1–2 floor-pulls actually land
on the remu step per seed.** The floor *does* keep remu's arm from going completely dark (the user's
intuition is correct that it's pulled) — but 1–2 pulls/seed against a 1/26 bug ≈ 0 finds. Measured: cTS
landed **6** total mutations on remu across **6 seeds**.

## 4. The deeper conflict: coverage objective ⟂ needle-in-haystack soundness bug
This is the generalizable point. Coverage-guided fuzzing optimizes **breadth/novelty** — reach new
locations and constraint families. This CVE requires **depth** — bombard *one* rare instruction with
INSTR_WORD flips until the ~1/26 rs2-alias lands. These objectives are **anti-correlated**:
- A rare instruction is maximally novel on its **first** hit, then yields **zero** new coverage.
- The bug pays off only on the **dozens of hits after** the first.

So a coverage-reward bandit systematically **withdraws budget from a target the instant it becomes
valuable for bug-finding.** Uniform's coverage-*blind* round-robin keeps hammering it by accident. The
"smarter" scheduler is strictly worse here — coverage-guidance is **counterproductive** for narrow,
low-probability soundness bugs localized at a rare instruction.

## 5. Why this is real, not a measurement artifact (the checks performed)
- **Output-based replay (indexing-independent):** every cTS INSTR_WORD accept — including all **7 at its
  single most-hammered arithmetic step (441)** — re-executes to the **honest `9000027`** (benign). V6-uniform's
  finds re-execute to **`0`** (remu-alias) / **`9000028`** (divu-alias) exactly. So cTS produced no
  accept-of-wrong, period.
- **Same code path / indexing:** V6-cTS routes through `arguzz_invoke.run` (`--inject`), identical to
  V6-uniform, so the 910-vs-6 attempt counts at remu (step 444) are directly comparable.
- **Indexing red herring resolved:** the zone-classifier (`A4_INSPECT` cycle indexing) labels step 441
  `core_div`, which made it *look* like cTS was hammering the division. But that is a *different* indexing
  from the `--inject` steps the race/replay use; in `--inject` indexing the division instructions are at
  444/449 (proven by uniform's output-confirmed finds), and step-441 mutations commit the honest value.
- **Non-arith sweep:** 1,230 non-arithmetic accepts replayed — **all benign**, 0 other-accept-of-wrong.

## 6. Hybrid inherits the blind spot
Hybrid_cTS uses the **same cTS scheduling** for its Arguzz surface → 5 attempts on remu, 1 on divu → **0
finds**. The Arguzz surface alone is necessary but not sufficient; with cTS scheduling on top, the rare
vulnerable instruction is starved just as in V6-cTS. (Hybrid's A4 surface also can't help — A4 cannot make
a coherent rs2-alias; see the coherence analysis.)

## 7. Implications for the thesis
1. **A4-vs-Arguzz complementarity holds** via V6-uniform: Arguzz's during-exec recompute finds the CVE
   that A4's post-exec single-cell mutation structurally cannot (coherence). Mirror of the Seam-B race.
2. **New secondary finding:** *for this bug, scheduling discipline matters as much as the mutation
   surface.* The during-exec surface is necessary; **uniform** scheduling is what actually delivers the
   find, and **coverage-guided (cTS) scheduling defeats it.** Coverage proxies that predicted "general
   exploration quality" are negatively predictive for this specific soundness discovery.
3. This sharpens (not weakens) the story: it cleanly separates *capability* (mutation surface →
   coherence) from *allocation* (scheduler → targeting), and shows the bug needs **both** the right
   surface (Arguzz) **and** the right allocation (uniform).

## 8. What would (hypothetically) fix cTS — for discussion only; Arguzz is NOT modified
- **Per-instruction arms** (remu its own arm) instead of `(kind, zone)` → the floor would protect it.
- **Exploitation/residual reward** for accept-of-wrong (or constraint-residue) instead of pure coverage
  novelty → the bandit would re-invest in a productive target.
- **Higher / step-level floor** so rare steps get more than ~1–2 pulls/seed.
These are listed only to make the mechanism precise. Per project constraint we do **not** modify Arguzz or
its schedulers; the cTS underperformance is reported as a characterization, and the round-2 design
(`CVE_RACE_ROUND2_GUEST_DESIGN.md`) keeps the schedulers fixed and varies the guest.

---
*Data: `a4/runs/iv_pos_9/race/cve_results/` (batches 1–3), `cve_replay_arith.json`,
`cve_replay_nonarith.json`. Schedulers: `a4/runs/iv_pos_7/drivers/v6_driver_v2.py` (ArguzzScheduler),
`a4/standalone/bandit_ts.py` + `semantic_arm_universe.py` (cTS). Floor: `IV_POS_8_D2_BERNOULLI_FLOOR_SPEC.md`.*
