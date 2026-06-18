# D2.B Batch 3 — Composer Report

**Date:** 2026-06-18  
**Branch:** `cloud2`  
**Predecessor commit:** `f81523c` (Batch 2)  
**Kickoff:** `D2B_BATCH3_COMPOSER_KICKOFF.md`

---

## Opus review of Batch 2 — Composer assessment

| Opus claim | Agree? | Notes |
|------------|--------|-------|
| Pushback #1: paging `extern_nextPagingIdx` live path | **Yes** | Opus accepted; scoped dead-arm claim is correct |
| Pushback #2: `pytest.xfail(strict=False)` API error | **Yes** | Runtime xfail takes reason only |
| Defer B.3 from arm universe for D2.G | **Yes** | Bandit waste documented; not implemented this batch |
| B.6/B.7 predicted dead (W-17) | **Yes — confirmed** | Attestation xfails; guard fires |
| B.4/B.5/B.8 predicted LIVE | **Partial** | B.8 LIVE ✅ (`cycle` family). **B.4/B.5 unexpectedly dead** on sha2-host |

**Pushback on Opus Batch 3 kickoff:** Spec §5.4 LIVE prediction for **B.4 and B.5 was falsified** on sha2-host. Same txn indices that fire `memory` for `TXN_PREV_CYCLE_MOD` / `TXN_PREV_WORD_MOD` accept fully when `addr` or `cycle` LSB is mutated. This is **not** the W-17 `set_cycle` mechanism — it is a **new witness-path finding** requiring audit extension (see below). Implementation and attestation are complete; attestation uses guard + xfail with `pytest.fail` if live rejection ever appears.

---

## Pre-kickoff sanity (executed)

```
git branch: cloud2
HEAD: f81523c d2.b batch 2
Batch 2 deliverables: present
a4_dump_post_mut_cycle_window: present
collect_cycle_field_diffs + guard: present
_cycle_state_enum.py: present
cargo build --release: success (~5 min)
```

---

## Implementation summary

| Kind | Rust | Python | Unit | Attestation outcome |
|------|------|--------|------|---------------------|
| B.4 `TXN_ADDR_MOD` | ✅ | ✅ | ✅ | **XFAIL — unexpected dead arm** |
| B.5 `TXN_CYCLE_PHASE_MOD` | ✅ | ✅ | ✅ | **XFAIL — unexpected dead arm** |
| B.6 `CYCLE_PC_MOD` | ✅ | ✅ | ✅ | **XFAIL — W-17 confirmed** |
| B.7 `CYCLE_STATE_MOD` | ✅ | ✅ | ✅ | **XFAIL — W-17 confirmed** |
| B.8 `CYCLE_DIFF_COUNT_MOD` | ✅ | ✅ | ✅ | **PASS — LIVE** (`cycle` Hook 3) |

**Infrastructure:** Extended `<a4_cycle_info>` and `<a4_post_mut_cycle_dump>` with `state`, `diff_count_0`, `diff_count_1` for B.7/B.8 Layer 3.

**Registry:** All 5 kinds in `MUTATION_KINDS`, `semantic_arm_universe`, `inspection_data`, CGC roles (B.4/B.5/B.8). `CYCLE_PC_MOD` added to `_MAJOR_FILTER_KINDS`.

---

## Hook 3 / rejection channel findings

| Kind | C1 | C2 | C3 family | Verifier | Classification |
|------|----|----|-----------|----------|----------------|
| B.4 | silent | silent | none | accept | Dead arm (unexpected) |
| B.5 | silent | silent | none | accept | Dead arm (unexpected) |
| B.6 | silent | silent | none | accept | W-17 dead arm (predicted) |
| B.7 | silent | silent | none | accept | W-17 dead arm (predicted) |
| B.8 | silent | varies | **`cycle`** | reject path | **LIVE** |

**Empirical contrast (step 1, sha2-host):**

| Mutation | txn 15415 | Result |
|----------|-----------|--------|
| `TXN_PREV_CYCLE_MOD` | prev_cycle change | `memory` + `cycle` + verify segment |
| `TXN_ADDR_MOD` | addr change | all silent, verifier accept |
| `TXN_CYCLE_PHASE_MOD` | cycle LSB XOR | all silent, verifier accept |

---

## Audit reconciliation

### W-17 predictions — CONFIRMED

B.6 and B.7 match B.3: trace mutates, guard fires, verifier accepts. Plan §6d predictions hold.

### B.4/B.5 — mechanism proven (W-18)

**Follow-up audit complete:** [`D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md`](./D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md)

**Verdict:** **TRUE DEAD ARM (mechanism-proven)** for both B.4 and B.5. **NOT W-16.**

Root cause is **not** W-17 set_cycle overwrite. It is **W-18 execution-derived witness keys**:

- `extern_getMemoryTxn(addrElem)` takes execution address; returns only `prevCycle`, `prevWord`, `word` — **not** `addr` or phase.
- Witness addr/phase bind to DSL `MemoryIO(memCycle, addr)` execution arguments (`mem.zir:65-75`, `88-101`).
- B.1/B.2 mutate fields **in the return tuple** → live. B.4/B.5 mutate fields used only for **sanity checks** → dead.

**FIE disambiguation (Opus Issue 1):** Option α (static) + Option β (`A4_NO_FAULT_INJECTION=1`) both run. FIE suppresses witgen **throws** on addr mismatch (without FIE, B.4 exits 101 panic); FIE does **not** suppress Hook 3 or verify segment. Silence on default runs is structural dead arm, not masked C1/C2/C3.

**B.8:** Predicted LIVE via `extern_getDiffCount` — **confirmed**. Hook 3 fires `cycle` family (not `memory`).

---

## Opus Batch 3 systematic audit — Composer response

| Opus issue | Priority | Composer action | Pushback? |
|------------|----------|-----------------|-----------|
| Issue 1: B.4/B.5 mechanism unproven | 🟥 | **`D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md` delivered** — verdict TRUE DEAD ARM | **Agree** — was the blocker; now closed |
| Issue 2: Inverted AUDIT NOTE wording | 🟧 | Fixed in `test_d2b_txn_addr_mod_attestation.py` + `test_d2b_txn_cycle_phase_mod_attestation.py` | **Agree** — spec predicted LIVE; contradiction is vs empirical dead-arm finding |
| Issue 3: B.4 cascade too permissive | 🟧 | Cascade tightened to `[]` (handler only mutates `addr`) | **Agree** — trace diff_signature checks trace, not witness cascade |
| Issue 4: Broader scan not in pytest | 🟨 | Documented in audit §A2 | **Agree** — parametrization deferred (runtime) |
| Issue 5: B.6/B.7 non-user cycles unproven | 🟨 | Audit §A1 grep enumeration | **Agree** — same W-17 paging caveat as B.3 |
| Minor: §9c scope expansion | 🟦 | Plan v0.13 §9c updated for 5 dead kinds | **Agree** |

**Major Pro-facing finding (Opus scope shift):** Among Pro's 8 requested A4 kinds, **3 live + 5 dead** on sha2-host. Surfaced as **NFP-11** in `IV_POS_8_NOTES_FOR_PRO.md`. Plan v0.13 adds **W-18**; spec v0.5.4 updates §3.4, §3.5, §5.4.

**Composer pushback on kickoff trichotomy:** Root cause (c) "FIE silencing C1/C2/C3" is **misleading as stated**. FIE is a witgen survival hook for sanity throws; it does not explain silent Hook 3 on default runs. The correct disambiguation: **(a) true dead arm** for channel silence; FIE relevant only for **methodology** (without FIE, B.4 crashes instead of completing witgen).

**Composer pushback on original spec §3.4:** Claim that FIE "produce constraint failures instead" of panic is **incorrect**. FIE skips the throw and witgen proceeds with execution-derived witness — no constraint failure. Spec corrected in v0.5.4.

---

## Documentation updates (delivered)

| Artifact | Update |
|----------|--------|
| `D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md` | New — mechanism proof + §A1/A2 |
| `IV_POS_8_D2_PLAN.md` | v0.13 — W-18, §6d empirical column, §9c scope |
| `IV_POS_8_D2_B_SPEC.md` | v0.5.4 — §3.4/§3.5 outcomes, §5.4 results |
| `IV_POS_8_NOTES_FOR_PRO.md` | NFP-11 dead/live split |
| Attestation tests | AUDIT NOTE fix + B.4 cascade `[]` |

---

## Test results

```
Batch 3 unit: 13 passed
Batch 3 attestation: 1 passed (B.8), 4 xfailed (B.4, B.5, B.6, B.7)
Post-audit patch verification: see pytest run below
```

Run: `A4_REAL_BINARY=1 pytest a4/standalone/tests/test_d2b_batch3_unit.py a4/standalone/tests/test_d2b_txn_addr_mod_attestation.py a4/standalone/tests/test_d2b_txn_cycle_phase_mod_attestation.py -v`

---

## Opus task compliance (txn audit kickoff)

| Kickoff requirement | Status |
|---------------------|--------|
| `D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md` with forced verdict | ✅ TRUE DEAD ARM |
| FIE disambiguation (α and/or β) | ✅ Both |
| §6 comparison table txn 15415 | ✅ |
| §A1 B.6/B.7 extern grep | ✅ |
| §A2 broader scan appendix | ✅ |
| Patch AUDIT NOTE wording | ✅ |
| Patch B.4 cascade `[]` | ✅ |
| W-18 + §6d + spec + NFP-11 | ✅ |
| Commit Batch 3 | ⏸ Pending explicit commit request |

---

## Recommendations (completed)

1. ~~§6d table: B.4/B.5 dead pending audit~~ → **Done** (W-18)
2. ~~W-18 watchlist~~ → **Done** (plan v0.13)
3. ~~NFP-11 for Pro~~ → **Done**
4. **D2.G:** Live A4 kinds on sha2-host = B.1, B.2, B.8 only among Pro's 8
5. **Do not drop implementations yet** — §9c postscript post-Batch-4 removes from `MUTATION_KINDS`

---

*End of Batch 3 report (updated post Opus audit + txn dead-arm audit).*
