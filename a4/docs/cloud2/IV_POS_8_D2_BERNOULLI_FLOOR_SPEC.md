# IV.POS.8 — Phase 2 Spec: Bernoulli Floor for the new cTS variants

**Version:** v1.0 — **LOCKED FOR IMPLEMENTATION** (authored by Opus-CP acting as D2-Opus, 2026-06-20)
**Phase:** New_Master §2 **Phase 2** (Bernoulli floor) · Pro: `ProG_Report_4.md` §Phase 2 + §5 Q1
**Governing plan:** [`New_Master.md`](New_Master.md) §2 Phase 2, §1 LOCKED-decisions row "D1 Decay"
**Backward companion / flags:** [`separate-planning/central-planning-1.md`](separate-planning/central-planning-1.md) §6.x Finding D, ⚑ F12
**Predecessor (closed):** D2.C (`IV_POS_8_D2_C_SPEC.md` v0.5, complete — Batches 1–4; full sweep 729 passed / 27 skipped)
**Baseline commit / tree:** working tree at D2.C-complete (729/27). New tests add to this.

---

## 0. Scope & non-goals

### 0.1 What this phase IS
Add a **per-pull Bernoulli floor mode** to `ConstrainedTSScheduler` so the exploration/exploitation split is **continuous in the floor fraction**, and **enable it only for `v6_cTS` and `hybrid_cTS`**. This implements Pro's Phase-2 directive verbatim:

```text
if rand() < floor_fraction:
    use floor exploration
else:
    use adaptive TS
```

It fixes **D1.A Finding D**: the current integer per-arm-quota floor (`target = floor_frac × epoch_size / n_arms`) supports only ~3 effective regimes (~0% / ~48% / ~96%), so a nominal `floor_fraction` of 0.35 or 0.20 does **not** behave continuously. With per-pull Bernoulli sampling, realized floor share ≈ `floor_fraction` exactly, and **gradient floor decay becomes mechanically testable** (it is not, today). The need grows with arm count (V6-cTS ~200–350 arms, Hybrid ~160–240 vs V5's 48), where integer per-arm quotas are even coarser.

### 0.2 What this phase is NOT (non-goals — do NOT do these)
- **Do NOT change `V5_control` behavior.** V5 is the deployed A4 archive baseline. `cTS_semantic_v2` and the two V5 decay variants (`cTS_semantic_v2_decayexp`, `cTS_semantic_v2_decayepoch`) keep the **integer-quota** floor unchanged. (Pro §Phase 2: "Do not replace the archived V5-control behavior.")
- **Do NOT build `V5_fresh_bernoulli`.** That ablation is optional/later per Pro and **must not block** this phase. (Deferred — §11.)
- **Do NOT replace the Beta-Bernoulli reward with a scalar bandit (Layer 2).** Out of scope (NFP-9; deferred to a follow-on). Untouched here.
- **Do NOT introduce a floor *decay* schedule into production for V6-cTS/Hybrid in this phase.** They use `ConstantFloor(0.55)` (New_Master §1 "Hybrid/V6-cTS = Bernoulli floor"; `_floor_schedule_for_strategy` already returns it). Swapping in a decay schedule (`ExponentialDecayFloor`, `EpochStageFloor`) is a **D1.E** decision; this phase only makes such a swap *meaningful* if it later happens.
- **Do NOT touch `bandit.py`, `semantic_arm_universe.py`, `arguzz_invoke.py`, `arguzz_bridge.py`, `v6_uniform_driver.py`, `v6_driver_v2.py`, or `workspace/risc0-modified/`** — all frozen. (V6-uniform uses `ArguzzScheduler`, not cTS — it is unaffected.)

### 0.3 Why now (sequencing)
New_Master §2 Phase 2: *"the Phase-3 checkpoint campaigns must NOT start until this phase is green."* Pro: "add Bernoulli before large Hybrid campaigns." So **this phase gates Phase 3 (the 4-variant checkpoint)**. It is orthogonal to the D2.C Arguzz bridge (already landed), so it can proceed immediately.

---

## 1. Background — the mechanism it replaces (verified against code)

`ConstrainedTSScheduler.select()` (`bandit_ts.py:203-272`) is a 4-tier waterfall. Each pull picks the **first** applicable tier:

| Tier | Condition | Pick | `mode` | RNG consumed |
|---|---|---|---|---|
| 1 **cold-start** | any arm with `pulls < cold_start_pulls_per_arm` (3) | round-robin over cold arms (`_cold_rr` counter) | `cold` | none (then step pick) |
| 2 **singleton** | any singleton arm with `pulls < forced_singleton_pulls` (5) | round-robin over needy singletons | `singleton` | none (then step pick) |
| 3 **quota floor** | any arm with `epoch_pulls < target`, where `target = floor_frac × epoch_size(100) / n_arms` | arm with min `epoch_pulls` | `floor` | none (then step pick) |
| 4 **adaptive TS** | else | argmax of Beta(α,β) samples | `adaptive` | `betavariate` × n_arms (then step pick) |

**Finding D (the bug this fixes):** in tier 3, `target` is a small real number (e.g. `0.55×100/48 = 1.146`), but `epoch_pulls` is an integer, so only integer crossings of `target` matter → ~3 regimes. The continuous `floor_frac` is lost. **Phase 2 replaces tier 3's *trigger* (quota) with a per-pull Bernoulli draw; tiers 1, 2, 4 are unchanged.**

**The floor *value* source is unchanged:** `_floor_target()` reads `self.floor_schedule.current(total_mutations=…, local_discoveries=…)` (`bandit_ts.py:180-187`). Bernoulli reuses **the same** `floor_schedule.current(...)` value — it only changes how that fraction is consumed. `floor_schedule` (value) and `bernoulli_floor` (consumption mode) are **orthogonal**.

---

## 2. Design — the Bernoulli floor (LOCKED)

### 2.1 New scheduler flag
Add to `ConstrainedTSScheduler.__init__`:
```python
bernoulli_floor: bool = False,   # default OFF → V5 back-compat (integer-quota path unchanged)
```
Store `self.bernoulli_floor = bernoulli_floor`.

### 2.2 The modified tier-3 branch in `select()`
Replace **only** the tier-3 block (current `bandit_ts.py:233-252`, the `# 3. Per-epoch coverage floor` else-branch through the end of the adaptive block) with a Bernoulli fork. Exact required semantics:

```python
else:
    # 3. Floor vs adaptive split
    if self.bernoulli_floor:
        # Phase 2 (Pro §Phase 2): per-pull Bernoulli floor — continuous mode share.
        frac = self.floor_schedule.current(
            total_mutations=self._total_mutations,
            local_discoveries=self._local_discoveries,
        )
        frac = min(1.0, max(0.0, frac))          # defensive clamp
        if self.rng.random() < frac:             # ── PINNED draw point (see §2.4) ──
            chosen = min(self.arms, key=lambda a: self.epoch_pulls[a])
            mode = "floor"
            exploration = True
        else:
            thetas = self._sample_thetas()
            sorted_arms = sorted(self.arms, key=lambda a: thetas[a], reverse=True)
            chosen = sorted_arms[0]
            score = thetas[chosen]
            mode = "adaptive"
            if len(sorted_arms) > 1:
                runnerup_arm = arm_id_for_decision(sorted_arms[1])
                runnerup_score = thetas[sorted_arms[1]]
    else:
        # Legacy integer per-epoch quota floor (V5 — UNCHANGED).
        target = self._floor_target()
        under = [a for a in self.arms if self.epoch_pulls[a] < target - _EPSILON]
        if under:
            chosen = min(under, key=lambda a: self.epoch_pulls[a])
            mode = "floor"
            exploration = True
        else:
            thetas = self._sample_thetas()
            sorted_arms = sorted(self.arms, key=lambda a: thetas[a], reverse=True)
            chosen = sorted_arms[0]
            score = thetas[chosen]
            mode = "adaptive"
            if len(sorted_arms) > 1:
                runnerup_arm = arm_id_for_decision(sorted_arms[1])
                runnerup_score = thetas[sorted_arms[1]]
```
> Implementation note: factor the duplicated adaptive block into a small private helper if preferred (e.g. `_adaptive_pick()` returning `(chosen, score, runnerup_arm, runnerup_score)`) **only if** doing so leaves the V5 (`bernoulli_floor=False`) RNG sequence byte-identical. If in any doubt, **duplicate the block** rather than refactor — the V5 golden traces are the law (§5).

### 2.3 Floor-pick semantics (LOCKED — do not improvise)
When the Bernoulli draw selects "floor", pick **`min(self.arms, key=epoch_pulls)`** — the least-covered-this-epoch arm. This is the **same inner pick** as the legacy quota floor, so the floor retains its coverage-balancing meaning (successive floor draws within an epoch round-robin across arms, because each floor pull increments that arm's `epoch_pulls`). 

**Rejected alternative:** uniform-random arm (`rng.choice(self.arms)`). Rejected because (a) it changes the floor's studied semantics from coverage-balancing to pure random, and (b) it consumes RNG differently. Keep coverage-balancing.

**`epoch_pulls` + epoch reset stay.** With Bernoulli, the epoch *target/quota* is bypassed but `epoch_pulls` is **reused** for the floor pick and the epoch reset (`_advance_state`, `bandit_ts.py:282-285`) still runs. This is intentional reuse, **not** dead code — do not remove the epoch machinery.

### 2.4 RNG draw order (PINNED — reproducibility contract)
In the Bernoulli path, per non-cold/non-singleton pull, the scheduler consumes RNG in **exactly** this order:
1. `self.rng.random()` — the Bernoulli floor/adaptive draw (**new**).
2. If adaptive: `self.rng.betavariate(...)` once per arm (via `_sample_thetas`), in `self.arms` order.
3. The step pick: `self.rng.choice(steps)` iff the arm has >1 valid step (unchanged, all tiers).

This order is **frozen by a new V6-cTS golden trace** (§6 Layer-2). Cold/singleton tiers consume **no** `random()`/`betavariate` (round-robin is deterministic via `_cold_rr`), so the Bernoulli draw is reached only after both hard-guarantee tiers are satisfied — early-campaign cold-start pulls are unaffected.

> **Single shared `self.rng`** is used (same stream as theta-sampling and step-choice). Do **not** add a second RNG. The V5 path never reaches line (1) because it takes the `else` (legacy) branch, so V5's stream is untouched.

### 2.5 Per-variant enablement (wiring)
Bernoulli is enabled **iff `selector_strategy in ARGUZZ_CTS_STRATEGIES`** (`= {"v6_cTS", "hybrid_cTS"}`, `fuzzer.py:143`). All V5 cTS variants → `bernoulli_floor=False`.

---

## 3. Locked decisions (Q&A)

| # | Question | Decision |
|---|---|---|
| **BF-Q1** | New `FloorSchedule` subclass, or a scheduler flag? | **Scheduler flag** `bernoulli_floor`. The floor *value* still comes from the existing `FloorSchedule`; Bernoulli changes only *consumption*. Orthogonal concerns. |
| **BF-Q2** | Which strategies get Bernoulli? | **`v6_cTS`, `hybrid_cTS` only** (`ARGUZZ_CTS_STRATEGIES`). V5 + V5 decay variants keep integer quota. |
| **BF-Q3** | Floor schedule for V6-cTS/Hybrid this phase? | **`ConstantFloor(0.55)`** (unchanged from D2.C `_floor_schedule_for_strategy`). Decay schedules are a D1.E concern; Bernoulli just makes them testable later. |
| **BF-Q4** | Floor-pick when Bernoulli says "floor"? | **`min epoch_pulls`** (coverage balancing, same as legacy). Not uniform-random. |
| **BF-Q5** | Extend `BanditDecision` (e.g. record drawn `frac`)? | **NO.** Keep it byte-identical (same rationale as D2.C ISS-6). D2.G derives realized floor share from `mode` counts in `bandit_decisions`; the schedule value is recomputable from `(total_mutations, local_discoveries)` logged per mutation. |
| **BF-Q6** | Interaction with `applied_accounting_mode`? | **None special.** The Bernoulli draw is in `select()` (pre-outcome). The floor-schedule "clock" (`_total_mutations`/`_local_discoveries`) advances in `_advance_state`, which in applied mode runs only on APPLIED — so the floor clock runs on **applied** pulls. Consistent and intended; document, no code. |
| **BF-Q7** | Clamp `frac`? | **Yes**, defensively to `[0,1]` (cheap; guards a misconfigured schedule). |
| **BF-Q8** | One batch or several? | **One batch** (B1): scheduler change + fuzzer wiring + tests + V5-unchanged golden trace + new V6-cTS golden trace. |

---

## 4. File-by-file changes

| File | Change | Est. LOC |
|---|---|---|
| `a4/standalone/bandit_ts.py` | (a) `__init__`: add `bernoulli_floor: bool = False` param + `self.bernoulli_floor`. (b) `select()` tier-3: Bernoulli fork per §2.2 (legacy path byte-identical). | ~20–30 |
| `a4/standalone/fuzzer.py` | At the cTS construction site (`_setup_v2_bandit`, the `ConstrainedTSScheduler(...)` call ~`fuzzer.py:816`), pass `bernoulli_floor=(self.selector_strategy in ARGUZZ_CTS_STRATEGIES)`. Optionally surface it in `campaign_params.extra_json` (see §4.1). | ~3–8 |
| `a4/standalone/tests/test_d2_bernoulli_floor.py` | **NEW** — mode-share linearity, decay continuity, cold/singleton preserved, applied-accounting clock, floor-pick semantics (§6 Layer-1). | ~120–180 |
| `a4/standalone/tests/test_d2_bernoulli_floor_golden_trace.py` | **NEW** — V6-cTS-shaped decision-seq golden trace pinning the §2.4 RNG order (§6 Layer-2). | ~40 + fixture |
| `a4/docs/cloud2/New_Master.md` | Flip Phase-2 row → DONE on completion; status line. | doc |
| `a4/docs/cloud2/IV_POS_8_D2_BERNOULLI_FLOOR_SPEC.md` | This spec — §12 changelog + §10 ISS annex updates. | doc |

### 4.1 `extra_json` provenance (recommended, low-risk)
So a campaign DB self-describes whether Bernoulli was active, add `"bernoulli_floor": <bool>` to the floor-schedule serialization in `campaign_params.extra_json` (alongside `_floor_schedule_extra`, `fuzzer.py:~693`). This is **append-only** to a JSON blob — it does **not** affect the V5 golden traces (V5 = `bernoulli_floor:false`, and the byte-identity golden trace is over **decisions/DB rows the scheduler emits**, not `extra_json`; confirm against the Tier-2 fixture's captured tables in pre-flight — if `campaign_params` is in the byte-identity snapshot, gate the new key so V5's serialized blob is unchanged, i.e. only emit the key for Arguzz strategies OR regenerate the V5 fixture only if it provably stays identical). **If this risks the Tier-2 fixture at all, skip it** — it is a nice-to-have, not required.

---

## 5. What must NOT change — the V5 byte-identity contract (existential)

The **single biggest risk** is that the shared construction site or the `select()` edit perturbs the V5 path. Hard requirements:

1. `bernoulli_floor` **defaults to `False`**; the V5 strategies (`cTS_semantic_v2`, `cTS_semantic_v2_decayexp`, `cTS_semantic_v2_decayepoch`) construct with `bernoulli_floor=False`.
2. With `bernoulli_floor=False`, `select()` takes the **legacy** branch (§2.2 `else`) and consumes RNG in the **identical** order as today — **no `random()` before `_sample_thetas`**.
3. These MUST stay green, byte-for-byte, after the change:
   - `test_d2c_golden_trace_v5_decision_seq.py` (Tier-1 decision sequence)
   - `test_d2c_golden_trace_v5_db_byte_identity.py` (Tier-2 DB byte-identity)
   - `test_d2a_back_compat_golden_trace.py`, `test_v5_bandit_skip_update.py`, `test_floor_schedule.py`, `test_bandit_ts.py`, `test_bandit_property.py`, `test_bandit_ts_adversarial.py`
4. **Frozen files** (do not edit): `bandit.py`, `semantic_arm_universe.py`, `arguzz_invoke.py`, `arguzz_bridge.py`, `v6_uniform_driver.py`, `v6_driver_v2.py`, `semantic_zones.py`, `arguzz_parser.py`, `workspace/risc0-modified/`.

---

## 6. Test plan

### Layer 1 — Bernoulli behavior (`test_d2_bernoulli_floor.py`, pure-Python, no binary)
Build a small synthetic `SemanticArmUniverse` (reuse the fixtures/helpers from `test_bandit_ts.py`; enough arms that cold-start completes well before N, e.g. ~10–20 arms, N≈4000) and assert:

1. **Mode-share linearity (the headline test — proves Finding D is fixed).** For `bernoulli_floor=True` + `ConstantFloor(p)`, drive N pulls (always `update_with_outcome(arm, APPLIED, success=0)` to advance the clock), counting `mode` over the **post-cold, post-singleton** pulls only. Assert realized `floor`-share ≈ `p` within tolerance (e.g. ±0.03 at N=4000) for **`p ∈ {0.20, 0.35, 0.55, 0.80}`**. The legacy quota path cannot produce 0.20 distinct from 0.35 — this test would fail on it. (Optionally include a contrast assertion: legacy `bernoulli_floor=False` with the same `p`s collapses to ≤3 distinct realized shares.)
2. **Decay continuity.** `bernoulli_floor=True` + `EpochStageFloor([(0,0.55),(2000,0.35),(4000,0.20)])`: measure floor-share in windows `[cold_end,2000)`, `[2000,4000)`, `[4000,N)` → ≈ 0.55 / 0.35 / 0.20 respectively. Proves gradient decay is now mechanically expressible.
3. **Cold-start + singleton still honored.** Every arm reaches `pulls ≥ cold_start_pulls_per_arm`; every singleton reaches `pulls ≥ forced_singleton_pulls`; no `floor`/`adaptive` mode appears before cold-start completes.
4. **Floor-pick is coverage-balancing.** Force `frac=1.0` (all-floor) for a few epochs and assert floor pulls spread roughly evenly across arms (min/max `epoch_pulls` differ by ≤1 within an epoch).
5. **Applied-accounting clock.** `bernoulli_floor=True` + `applied_accounting_mode=True`: feed a mix of APPLIED/SKIPPED outcomes; assert the floor schedule's effective clock = APPLIED count (mode-share measured over applied pulls still ≈ `p`), and SKIPPED pulls do not advance `_total_mutations`.
6. **Determinism.** Same seed + same config → identical `(mode, arm_id, step)` sequence across two runs.

### Layer 2 — V6-cTS golden trace (`test_d2_bernoulli_floor_golden_trace.py`)
Generate a decision-sequence fixture (like the Tier-1 V5 golden trace, but `bernoulli_floor=True`, `ConstantFloor(0.55)`, fixed seed, modest N≈200, small fixed universe) and assert byte-identity on re-run. This **pins the §2.4 RNG draw order** so future refactors can't silently drift the new variant.

### Layer 3 — V5 unchanged (existing gates)
Run the §5.3 list; all must pass byte-identical. This is the acceptance gate, not a new test.

### Layer 4 — fuzzer wiring smoke (mocked, ≤10 real mutations / stubbed)
Assert that constructing the fuzzer with `selector_strategy="v6_cTS"` (and `"hybrid_cTS"`) yields a `ConstrainedTSScheduler` with `bernoulli_floor is True`, and with `"cTS_semantic_v2"` yields `bernoulli_floor is False`. Pure-construction assertion — **no real binary** (or ≤10 if a real-binary path is unavoidable; **>10 real mutations → POS**, per the §15 POS-run policy inherited from D2.C).

> **POS:** This phase is pure-Python scheduler logic. No new real-binary campaign is required. Do **not** dispatch a POS job for Phase 2. (The real-binary validation of Bernoulli-on-V6 happens implicitly in Phase 3's checkpoint campaigns, which this phase gates.)

---

## 7. Composer kickoff — directives

**Read first, in order:** (1) this spec end-to-end; (2) `bandit_ts.py:126-308` (the scheduler — `select()` and `_advance_state` especially); (3) `fuzzer.py:679-825` (`_floor_schedule_for_strategy`, `_setup_v2_bandit`, the construction site) + the strategy-family constants (`fuzzer.py:132-151`); (4) `tests/test_bandit_ts.py` + `tests/test_floor_schedule.py` (conventions + universe fixtures); (5) `tests/test_d2c_golden_trace_v5_decision_seq.py` (golden-trace pattern to mirror in Layer-2).

**Pre-flight (run BEFORE editing — record results in the report):**
```bash
# 1. Baseline green (expect 729 passed / 27 skipped)
python -m pytest a4/standalone/tests -q
# 2. V5 golden traces pass NOW (you must keep these byte-identical)
python -m pytest a4/standalone/tests/test_d2c_golden_trace_v5_decision_seq.py \
                 a4/standalone/tests/test_d2c_golden_trace_v5_db_byte_identity.py -q
# 3. Confirm the construction site + family constants
grep -n "ConstrainedTSScheduler(" a4/standalone/fuzzer.py
grep -n "ARGUZZ_CTS_STRATEGIES\|CTS_SEMANTIC_V2_FAMILY" a4/standalone/fuzzer.py
# 4. Confirm whether campaign_params is inside the Tier-2 byte-identity snapshot
#    (decides whether §4.1 extra_json key is safe — if it is in-snapshot, gate or skip it)
grep -n "campaign_params" a4/standalone/tests/test_d2c_golden_trace_v5_db_byte_identity.py
```

**Tasks:**
- **B1.1** — `bandit_ts.py`: add the `bernoulli_floor` param (§2.1) + the tier-3 fork (§2.2). Legacy branch byte-identical; **no `random()` before `_sample_thetas` in the legacy path.**
- **B1.2** — `fuzzer.py`: pass `bernoulli_floor=(self.selector_strategy in ARGUZZ_CTS_STRATEGIES)` at the construction site (§2.5). (Optional §4.1 `extra_json` key only if pre-flight #4 proves it safe.)
- **B1.3** — `test_d2_bernoulli_floor.py` (Layer-1, six assertions §6.1–6.6).
- **B1.4** — `test_d2_bernoulli_floor_golden_trace.py` + fixture (Layer-2, §2.4 RNG-order pin).
- **B1.5** — Run the full sweep + the V5 golden gates; report counts. Update §12 changelog + New_Master Phase-2 row → DONE.

**Stop-and-report triggers:** (a) any V5 golden trace changes by even one byte → **stop**, the legacy branch is not byte-identical; (b) pre-flight #1 ≠ 729/27 → reconcile before starting; (c) you find yourself editing any frozen file (§5.4) → stop.

---

## 8. Acceptance checklist
- [x] `bernoulli_floor` param added; defaults `False`; stored.
- [x] `select()` tier-3 Bernoulli fork per §2.2; floor-pick = min `epoch_pulls` (§2.3); RNG order per §2.4.
- [x] `fuzzer.py` enables Bernoulli **iff** `ARGUZZ_CTS_STRATEGIES`; V5 variants `False`.
- [x] Layer-1 tests pass — **mode-share linear for p ∈ {0.20,0.35,0.55,0.80}** (Finding D fixed), decay continuity, cold/singleton honored, applied-clock, floor-pick balancing, determinism.
- [x] Layer-2 V6-cTS golden trace added + green (RNG order pinned).
- [x] **V5 byte-identity: Tier-1 + Tier-2 golden traces byte-identical** (the existential gate).
- [x] Full sweep green, count = 757 passed / 27 skipped (+12 new tests vs pre-B1 baseline of 745; D2.C report cited 729 at lock time).
- [x] No frozen file touched; `BanditDecision` unchanged.
- [x] New_Master Phase-2 row → DONE; §12 changelog updated.

---

## 9. Risks / potential issues (flag ledger for this phase)

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| **PI-1** | Shared construction site / `select()` edit perturbs the **V5 path** → golden traces drift. | **Existential** | `bernoulli_floor=False` default + legacy branch byte-identical + the two V5 golden gates as hard acceptance (§5). If refactoring the adaptive block risks it, **duplicate instead** (§2.2 note). |
| **PI-2** | RNG draw order not pinned → V6-cTS irreproducible / silent drift in later phases. | High | §2.4 pinned order + Layer-2 golden trace. |
| **PI-3** | Composer improvises floor-pick (uniform random) → changes studied floor semantics + RNG consumption. | Med | BF-Q4 LOCKS min `epoch_pulls`; Layer-1 test 6.4 asserts balancing. |
| **PI-4** | V5 **decay** variants (`decayexp`/`decayepoch`) accidentally get Bernoulli → alters D1.A reproducibility. | Med | Gate is `ARGUZZ_CTS_STRATEGIES` only; decay variants are not in it. (If D1.E later wants Bernoulli decay, that's a D1.E spec.) |
| **PI-5** | Expectation mismatch: Phase-2 ships **ConstantFloor(0.55)** for V6-cTS/Hybrid, not decay — so the *immediate* effect is "exactly 55% floor share" vs the quota's ~48%, **not** decay-in-production. | Low (clarity) | Documented (§0.2, BF-Q3). Bernoulli's value this phase = precision + unlocking testable decay for D1.E, not decay itself. |
| **PI-6** | `extra_json` `bernoulli_floor` key (§4.1) lands inside the Tier-2 byte-identity snapshot → breaks V5 gate. | Low | Pre-flight #4 checks; gate the key to Arguzz strategies or **skip it** (it's optional). |
| **PI-7** | Epoch machinery looks vestigial under Bernoulli → someone "cleans it up" and breaks the floor pick / V5 path. | Low | §2.3 states it's intentional reuse; do not remove. |
| **PI-8** | `bandit_decisions` not actually logged for `v6_cTS`/`hybrid_cTS` → D2.G can't measure realized floor share. | Low | Verify in pre-flight that D2.C wired decision logging for the Arguzz cTS path; if not, log a follow-up (not a blocker for Phase 2 correctness, but needed before Phase 4 analysis). |

---

## 10. Tracked implementation issues (LIVING ANNEX)
*(None open at lock. Composer adds `ISS-*` rows here as Batch B1 surfaces them, mirroring the D2.C §15 convention.)*

---

## 11. Sequencing & dependencies
- **Blocks:** Phase 3 (New_Master §2 Phase 3 — the `V5_control / V6_uniform / V6_cTS / Hybrid_cTS` checkpoint). Do not start Phase-3 campaigns until this is green.
- **Independent of:** the D2.C Arguzz bridge (landed), D2.D variant-CLI wiring (can pipeline; D2.D consumes the enablement but does not depend on it being merged first beyond the scheduler flag existing).
- **Deferred (explicitly not here):** `V5_fresh_bernoulli` ablation (optional/later, must not block); Bernoulli-decay for D1.E; Layer-2 scalar reward bandit (NFP-9).
- **Carry-forward (unchanged by this phase):** ⚑ F12 (run N=10000 for V6-cTS/Hybrid in Phase 3/D2.F for cold-start fairness); ISS-1 D2.G fault-corroboration residual.

---

## 12. Changelog
| Date | Author | Version | Notes |
|---|---|---|---|
| 2026-06-20 | Composer | v1.0 DONE | B1 implemented: `bernoulli_floor` flag + tier-3 fork; fuzzer wiring for `ARGUZZ_CTS_STRATEGIES`; 12 new tests; sweep 757/27; V5 golden traces byte-identical. Report: `composer/D2_BERNOULLI_FLOOR_B1_COMPOSER_REPORT.md`. |
| 2026-06-20 | Opus-CP (acting D2-Opus) | v1.0 LOCKED | Initial spec. Bernoulli floor = scheduler flag (not a FloorSchedule subclass); tier-3 fork only; `ARGUZZ_CTS_STRATEGIES` gate; min-`epoch_pulls` floor pick; pinned RNG order + V6-cTS golden trace; V5 byte-identity as existential gate. Grounded in `bandit_ts.py:203-272/180-187`, `fuzzer.py:679-825/132-151`, `ProG_Report_4.md §Phase 2`, New_Master §1–2. |
