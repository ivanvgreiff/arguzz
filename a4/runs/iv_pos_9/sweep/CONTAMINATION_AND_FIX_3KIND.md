# IV.POS.9 Track-B — 3-kind binary-mismatch contamination: verification, impact, fix, re-run

**Severity: high (invalidates part of the sweep).** A binary mismatch caused 3 A4 mutation kinds to be
**silently skipped** on the sweep binaries, recording no-op mutations as `applied`/`accepted`.
Discovery write-up (Track A / cross-track): `THREE_KIND_INVESTIGATION_REPORT.md`. This document is the
**Track-B canonical record**: independent verification, root cause, exactly which jobs are affected,
impact on our reported findings, the applied fix, and the re-run plan.

---

## 1. The bug
The sweep guest binaries (g1/g2/g3) were built from `risc0-clean-28e53771` (Track-B worktree, HEAD
`93bda33b`), which **lacks** the witgen handlers for three A4 mutation kinds:
`TXN_PREV_WORD_MOD`, `TXN_PREV_CYCLE_MOD`, `CYCLE_DIFF_COUNT_MOD`.
Those handlers were added later, in commit **`6556e8d7`** ("Commit A4_MUTATION_CONFIG and mutation
replay hooks in witgen", witgen-only, +345/-2). The reused **g0 baseline** (D2.F/POS.8) was built from
a binary that **had** them. So g0 and g1/g2/g3 ran on **different mutation engines**.

On a binary without a handler, the kind hits the fallback at `witgen/mod.rs` → emits
`<a4_error>{"error":"invalid config",...}` → **trace unchanged** → an honest proof of the *unmodified*
execution → the verifier **accepts**. The Python fuzzer still logs `outcome=applied` with `orig≠mut`,
so the DB shows a benign-looking "accept" that never actually happened.

## 2. Independent verification (reproduced, not taken on faith)
| leg | check | result |
|---|---|---|
| source | `grep` the 3 kinds in `witgen/mod.rs` | clean tree = **0** handlers; `risc0-modified` = **3** each |
| binary | `strings` deployed g1 binary | **0** for all 3 kinds (but MEM_VAL_MOD / INSTR_TYPE_MOD present) |
| data | g1·V5 accepts by kind | **1534 = 512 CYCLE_DIFF + 509 TXN_PREV_CYCLE + 513 TXN_PREV_WORD**, nothing else |
| data | g1·Hybrid accepts by kind | 731 of 805 are the 3 kinds (74 real INSTR_WORD_MOD accepts) |
| lineage | `6556e8d7^` | parent **is `28e53771`** (our base) → handlers were added *after* our tree forked |

## 3. Root cause (ours)
The **§0.1 "G0-reuse" optimization** in `IV_POS_9_B3_SWEEP_CAMPAIGN_SPEC.md`. We reused the D2.F g0
baseline (a binary with the 3 handlers) and built the new guests from `28e53771` (without them). The
spec's validity argument — *"the g0 circuit + guest are unchanged on 28e53771"* — was wrong: D2.F's
binary carried the D2.B mutation handlers our tree predates. The spec even defined a **reuse-validation
gate** ("build a short V5 G0 run on the Track-B binary and confirm its loc/CGC trajectory matches the
D2.H G0 DB; if it diverges, re-run fresh") — **it was not run**; the weaker `0xDEADBEEF` functional-
equivalence check passed because it never exercises the injection path.

## 4. Affected jobs
A job is affected iff its variant **pulls** the 3 kinds **and** runs on the clean (un-patched) binary.

| variant | uses 3 kinds? | sweep jobs (g1/g2/g3 × 3 seeds) | status |
|---|---|---|---|
| **V5_control** (A4) | yes | 9 | **CONTAMINATED** (~31% of pulls = silent no-ops) |
| **Hybrid_cTS** | yes (A4 kind set) | 9 | **CONTAMINATED** (~16% of pulls) |
| V6_uniform (Arguzz) | no | 9 | **VALID** |
| V6_cTS (Arguzz) | no | 9 | **VALID** |
| g0 baseline (d2f reuse) | yes — but on the *modified* binary | 12 (reused) | internally OK but **wrong binary for comparison** |

**18 of 36 sweep jobs contaminated** (all V5 + all Hybrid). The 18 V6 jobs are clean.

## 5. Impact on Track-B findings (corrections to MASTER_REPORT)
- **RETRACT F2** ("benign-candidate surface is guest-dependent; g1·V5 1534 vs g0·V5 0"). The 1534 are silent skips (binary artifact), not benign accepts; the 0-vs-1534 gap is a binary mismatch, not a guest effect.
- **Amend Q3**: drop the "1534 benign accepts" narrative. The expected-value comparison (A4 E[#global|fire]=3.0 vs Arguzz 9.8–10.7) was computed over kinds that *actually fail* (implemented), so that comparison survives; only the skipped-kind framing is removed.
- **V5/Hybrid CGC undercounted** on g1/g2/g3 (the 3 kinds contribute 0 global failures) → the "CGC narrower on g1 for V5" reading is confounded.
- **UNAFFECTED / still valid:** Q2 (Arguzz wins CGC), F6 + the bypass/destroy evidence (all V6; both example kinds — LOAD_VAL_MOD, POST_EXEC_REG_MOD — are implemented Arguzz kinds), and the **headline Arguzz-global / A4-local / Case-B story** — supported by the correct-binary g0 (V5 CGC 337 < V6_uniform 428 < V6_cTS 560) and all V6 data.

## 6. Fix (applied)
1. **Cherry-picked `6556e8d7` onto the Track-B clean worktree** (its parent is `28e53771`, so a clean
   replay; witgen/mod.rs only, +345/-2). New Track-B HEAD = **`53c21894`**.
   - Verified: `load_rs2` (in `rv32im.rs`, *not* in the patch) untouched → stays **load_rs2=1**;
     `planted_bug` is a build-time env (`A4_PLANTED_BUG=none`) → unchanged. Isolation preserved
     (patched in Track-B's own worktree; **`risc0-modified` / Track A not touched**).
2. **Rebuild all 4 guest binaries** (g0_baseline, g1, g2, g3) from `53c21894`; the fingerprint guard
   self-check must still report `planted_bug=none, load_rs2_present=1` (new guest_image_ids).
3. **Post-build verification:** replay a TXN_PREV_CYCLE_MOD injection on a rebuilt binary and confirm it
   now **applies** (produces failures / rejects) instead of emitting `invalid config`.

## 7. Re-run plan (POS, same 5 nodes: pact stoi idex meld tinyman)
- **Re-run V5_control + Hybrid_cTS on all 4 guests × 3 seeds = 24 jobs** — including **g0 fresh** (no
  more cross-binary reuse). ~24–30 h on 5 nodes (resume-safe chain, ~5.8 h/batch).
- **Keep** the 18 V6_uniform/V6_cTS results (binary-invariant for their kinds). g0 V6 reuse stays valid
  too (V6 never touches the 3 handlers).
- Update GUEST_SPECS guest_image_ids to the rebuilt binaries; rebuild + redeploy the bundle; dispatch
  via the Track-B chain_dispatcher as before.

## 8. Prevention (policy)
- **No cross-binary baseline reuse.** Always build g0 on the *same* Track-B binary as the new guests.
- **Add a runner guard** (shared fuzzer follow-up): if the host emits `<a4_error>invalid config` for the
  requested kind, record `outcome=not_applied` — never `applied`/`accept`. Makes a silent skip
  impossible to mis-record.
- **Actually run the reuse/equivalence gate**, and make it exercise the injection path (not just the
  committed-output `0xDEADBEEF` check).

*Generated 2026-06-25. Fix HEAD 53c21894. Re-run tracked in MASTER_REPORT §2/§3.*
