# Phase 7d Inc 3d Phase B — Opus analysis of Composer's POS run

**Date:** 2026-06-12
**Auditing:** `PHASE_7D_INC3D_B_COMPOSER_REPORT.md` + 20 logs in `a4/audits/audit_output/inc3d/p{1,2}/`
**Verdict on Composer's work:** rigorous, accurate, plumbing solid. All headline numbers verified against raw data. One sub-finding (meld P2 index 6 → mut 5) has a small index-counting discrepancy, noted below.

---

## §1 Verification of Composer's headline claims

| Claim | Verification |
|-------|--------------|
| B1 `mut="…"` attrs on 100% of verbose blocks | **PASS** — `grep -oE 'mut="[^"]*"'` returns full 64-char SHA-256 on every block |
| flareCtrlA[i] `mut=` == flareCtrlB[i] `mut=` (paired runs aligned) | **PASS** — verified blocks 0–4 and block 28 directly; identical SHAs |
| flareCtrlB witgen `value="1"` at counter index 28 (0-based) | **PASS** — line 13353 is exactly the 29th witgen counter; all other 48 are `value="0"` |
| DB mut 30 (`INSTR_WORD_MOD_FULL step=3541`) flipped `delta_T 0→1` between A and B | **PASS** — A=0/reward=0.1953, B=1/reward=0.1989; mutations 28, 29, 31, 32 are byte-identical |
| Race is NOT solely from `std::set<std::string>` verbose tracking | **PASS** — meld P2 raced without verbose enabled |

**No issues with Composer's bundling, dispatch, or instrumentation.**

---

## §2 NEW finding from B2 trace mining — the exact race window

Sliced `<a4_ftw>` traces by verbose-block boundaries for flareCtrlA[28] vs flareCtrlB[28] (mut 30).

### Trace structure
- A: 456 `<a4_ftw>` lines in block 28
- B: 456 `<a4_ftw>` lines in block 28
- 272 lines identical
- 184 lines unique to A / 184 lines unique to B (perfectly symmetric — same number of calls, different values)

### Divergence is structured, not noise

All 184 differing lines on each side concentrate on **exactly 23 consecutive cycles** spanning `cycle=22171 … 23169`:

```
cycle=22171: 8 lines (A-only) / 8 lines (B-only), 0 in common
cycle=22532: 8 / 8 / 0
cycle=22584: 8 / 8 / 0
cycle=22623: 8 / 8 / 0
...
cycle=23169: 8 / 8 / 0
```

- Exactly **8 lines per cycle** (matches Poseidon2 lane count — full state)
- ZERO overlap on diverging cycles (every lane differs)
- All diverging lines share `userCycle="3929"`, `pc="0x00000000"`, `major="9"`, `minor="5"`
- All cycles BEFORE 22171 (i.e. 21205, 21527, 21849) are byte-identical between A and B

This is **NOT** a single rare context appearing on B. It's a **full Poseidon2-state divergence at userCycle 3929 that propagates for 23 cycles**, after which the field re-converges.

### The single lowIsZero=1 event (the B3 counter hit)

Among B's 184 unique lines, exactly ONE has `lowIsZero="1"`:
```
cycle="22662" userCycle="3929" pc="0x00000000" major="9" minor="5"
arg0="1841627136" low="0" high="28101" lowIsZero="1"
```

In A, cycle 22662 has 8 lines, all with `lowIsZero="0"` and **different** `(arg0, low, high)` values.

So the racy bit is: at one specific Poseidon2 lane in cycle 22662, B's permuted output had its low 16 bits == 0; A's did not. That triggers `EQZ@FTW291:291` in B (which adds `FTW291:291|9|5` to the touch set) but `EQZ@FTW291:294` in A (which adds `FTW291:294|9|5` instead).

**The `low=0` is a downstream consequence, not the race itself.** The race is whatever upstream computation produces different Poseidon2 inputs at userCycle 3929 between A and B.

---

## §3 Updated hypothesis ranking

| # | Hypothesis | Status |
|---|------------|--------|
| 1 | Parser/measurement artifact | **REJECTED** — B1 mut=SHA alignment is exact, divergence is structural |
| 2 | `std::set<std::string>` verbose-set perturbation | **REJECTED** — meld P2 raced without verbose |
| 3 | Verbose-block / mutation misalignment | **REJECTED** — direct DB↔verbose↔B3 join verified |
| 4 | Poseidon2 internals nondeterminism | **REJECTED** — 21205, 21527, 21849 Poseidon2 cycles are identical; the algorithm is deterministic |
| 5 | **Race in upstream witgen feeding Poseidon2 input at userCycle 3929** | **NEW — best fit** — full 8-lane divergence at a specific user cycle |
| 6 | Asymmetry (B always racy) | **REJECTED** — meld P2 has A racy, B clean; Inc 3c was a stochastic streak |

Hypothesis 5 has two sub-hypotheses:

- **5a — Uninitialized read in executor handling out-of-bounds memory access.** Mut 30 is `LW x13, 53(x0)` (load word from low memory). If the executor's memory layer reads from an unmapped or stale page, the value depends on prior allocator state and differs between A and B. This loaded value feeds Poseidon2 input via the page-image hash.

- **5b — Real data race in compute_accum parallel phase.** Even though witgen is sequential (`kStepModeSeqForward` when `A4_COVERAGE_TOUCH=1`), `compute_accum` runs in parallel and feeds intermediate state back to witness buffers used by later cycles' Poseidon2. If two rayon threads write/read overlapping cells without sync, results differ. But this would only happen if accum runs BEFORE witgen at userCycle 3929 — needs verification.

**5a is more likely** because:
- All 4 racy mutations Composer found across Inc 3c/3d are memory-affecting (`MEM_VAL_MOD`, `STORE_OUT_MOD`, `INSTR_WORD_MOD_FULL`, `PRE_EXEC_REG_MOD`).
- Mut 30's `LW x13, 53(x0)` reads from address 53 — almost certainly inside the ELF text section or unmapped.
- WSL2 local non-reproducibility is consistent with WSL2's deterministic page allocation vs real Linux's variable page reuse.

---

## §4 meld P2 — index counting discrepancy (minor)

Composer said: "B3 counter: melddA witgen value="1" at index **6** (~mut 4-5)".
My measurement: melddA witgen `value="1"` at **index 3** (0-based, 4th counter pair).

DB shows:
- mut 4 = `MEM_VAL_MOD step=1643` — identical A/B, delta_T=0/0
- mut 5 = `PRE_EXEC_REG_MOD step=834` — A delta_T=1, B delta_T=0, reward differs ← **the racy one**

If B3 counter index 3 maps to DB mut 5, there's an off-by-one between B3 counters and DB ids. Same off-by-2 we see for flare (block 28 ↔ mut 30). The pattern (counter index = DB id − 2) is consistent.

I'll align this when updating `B7_verbose_touch.py` — the off-by-2 likely comes from the first mutation NOT producing a verbose block (sequencer quirk we already knew about from Inc 3c phase A).

**Asymmetry reversed for meld P2 (A racy, not B)** — this REFUTES the "B always racy" pattern that Inc 3c suggested. The directional asymmetry was a stochastic streak, not a structural property.

---

## §5 Action items (updated for Opus)

| # | Action | Owner | Priority |
|---|--------|-------|----------|
| 1 | Update `B7_verbose_touch.py` to use B1 `mut=` attrs for exact alignment (no fuzzy `_candidate_block_indices` heuristic) | Opus | High — needed for future scale runs |
| 2 | Build a `B2_ftw_diff.py` that slices `<a4_ftw>` traces by verbose-block boundaries and dumps the structured per-cycle diff (like the table in §2) | Opus | High |
| 3 | Investigate hypothesis 5a: instrument the memory subsystem to log address+value of each LW/SW between userCycle 3500 and 4000 for mut 30. If A and B see the same loads but produce different Poseidon2 inputs, the race is in `compute_partial_image` or page hashing | Opus → user (if zkVM patches needed, new B-branch instrumentation) | Medium |
| 4 | Octorand recapture (~100 more pairs) to confirm Inc 3c's 1/100 rate | Composer | Low — we have enough signal from flare/meld |
| 5 | Confirm hypothesis 5b is ruled out: dump the sequence of (witgen[c], accum[c]) callbacks around userCycle 3929 to verify witgen ran sequentially up to that point | Opus | Low — only if 5a doesn't pan out |
| 6 | Local replay attempt: extract mut 30 (`INSTR_WORD_MOD_FULL step=3541 word=55584387`) and the exact guest+host bundle, run sequentially N=200 on WSL2. If still 0/200, the race is POS-platform-bound (confirmed in Phase A but worth one more shot with the new build) | Opus | Low |

---

## §6 What the data tells us (summary for non-instrumentation readers)

The race is **real, structurally large** (full Poseidon2 state divergence over 23 cycles), and **NOT a measurement artifact** (B1 attributes prove paired-run alignment is exact).

The visible "rare extra context on B" is just one downstream lane out of 184 differing values. The root cause is upstream of Poseidon2, at a specific user cycle (3929 for flare mut 30), and is sensitive to the *kind* of memory-touching mutation.

This is good news for fuzzing soundness work: the diagnostic captures we now have can pinpoint the exact compute step where state diverges, which is much more localized than "B7 sometimes flips intermittently". The bug is in how the executor or witness generator handles edge-case memory operations, and we should be able to localize it further with one more round of instrumentation (hypothesis 5a / action item 3).
