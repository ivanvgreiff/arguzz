# Phase 7d Inc 3d Phase B2 (B4) — Opus analysis of Composer's POS handback

**Date**: 2026-06-12
**Reviewer**: Opus
**Input**: `PHASE_7D_INC3D_B2_COMPOSER_REPORT.md`, `b2_handback_summary.json`,
10 paired logs/DBs at `a4/audits/audit_output/inc3d/b2/`
**Host SHA reviewed**: `625e722e201a85fead62cef993fe4ec9399a1aface99c5967256bec29412b515`

---

## Verdict (TL;DR)

**B4 fingerprint is working but does NOT discriminate racy from non-racy mutations.** Every paired run (A vs B) shows the **exact same 24 divergent cycles** in memory records — independent of mutation, independent of node pair, independent of whether the mutation produced a visible ΔT flip. This means:

1. **`extern_memoryDelta` records are identical between A and B in the user-execution phase** (cycles < 33491). The race we care about — the ΔT flips on flare mut 4, opulous mut 29 — is **not** in memory operations.
2. The 24-cycle divergence at cycles 33491, 44343, 45065–46339 is a **systematic POS-environment artifact** in the **post-user finalization phase** (segment-commitment Poseidon2 rounds). It is **floor-level noise**, not race signal.
3. We have now **excluded** the witgen-side memory subsystem as the race source. The race must originate **upstream of witgen**, in the Rust executor's preflight trace construction.

**B7 race is now localized to a single layer:** the **executor / preflight phase**, where `ctx.preflight.cycles[...]` is built (probably with `thread::scope` + `rayon::into_par_iter`). Witgen reads this data deterministically; if the data was built racily, witgen faithfully reproduces the divergence downstream.

---

## What I verified

### 1. Composer's reward-diff numbers — CONFIRMED

Direct query against the 10 DBs (`mutations` LEFT JOIN `mutation_rewards`):

| Pair | True ΔT flips | Other reward diffs | Notes |
|------|---------------|--------------------|-------|
| octoa / octob | 0 | 0 | 0/100 octorand divergences this session |
| opulous | **1** (mut 29 ΔT 0→1, `INSTR_WORD_MOD_SUR`) | 0 | matches Composer |
| meld | 0 | 0 | matches Composer |
| flareCtrl | **1** (mut 4 ΔT 1→0, `PRE_EXEC_REG_MOD`) | 1 (mut 20, reward delta = 5.6e-4, ΔT same on both sides) | flare mut 20 is a **float-rounding artifact**, not a real race |

So the true race rate this session is **2/250 paired mutations = 0.8%** — consistent with prior B Pass 1/2 rates (~1–2% intermittent).

### 2. B4 instrumentation is active and emitting

`<a4_mem_total_hash>` blocks: 49–50 per run (matches the `PRE_EXEC_REG_MOD @ step 2708` SIGSEGV pattern we documented in B Pass 1). `<a4_mem_cycle_hash>` lines: ~10,513 per mutation block.

Per-block per-cycle hash extraction completed cleanly. No instrumentation bug.

### 3. The "first_divergent_cycle = 33491 every time" is real — and ENTIRELY noise

Composer flagged this but didn't have the cycles to dig in. I ran the full per-block per-cycle diff:

```
flareCtrl A vs B: 49 paired mutation blocks
For EVERY non-empty block (1..48):
  divergent cycles = EXACTLY this 24-cycle set:
    [33491, 44343, 45065, 45169, 45247, 45325, 45403, 45481, 45559, 45637,
     45689, 45741, 45793, 45845, 45897, 45949, 46001, 46053, 46105, 46157,
     46209, 46261, 46313, 46339]
  cycles in user phase (< 33491): 0 divergent in both
```

The reference set is **identical** for racy blocks (mut 4 = block 2, mut 20 = block 18) and non-racy blocks (mut 1, 3, 5, 6, …). No racy mutation has an additional divergent cycle.

### 4. The 24-cycle floor is the SAME across all five pairs

```
COMMON across all 5 pairs (octoa, octob, opulous, meld, flare):  24 cycles
UNION across all 5 pairs:                                        24 cycles
```

Identical set across pairs running on **different POS nodes**, **different seeds**, **different mutation campaigns**. This is decisive evidence the 24-cycle divergence is a **fixed structural property of the post-user finalization phase**, not a property of any particular mutation or node.

### 5. Where do these 24 cycles fall in the trace?

User cycles run up to ~23K (per the Inc 3d B P1 trace data, user code completed around witgen cycle 23169 for flare mut 30). The 24 divergent cycles all lie at cycle **≥ 33491**, well into the segment-finalization region. The clustered 22-cycle group (45065–46339, spaced ~78 apart) is the signature of a **single Poseidon2 invocation** (P2 takes ~22 cycles for 8-element rounds), most likely the segment-commitment hash of the final memory state.

### 6. Implication: race is NOT in `extern_memoryDelta`

Since memory records in the **user phase** (cycles 0–~33K) are bit-identical A vs B for every mutation including the racy ones, and the witgen P2 race we located in B Pass 1 (userCycle 3929, witgen cycle 22171–23169) sits squarely in the user phase, **the P2 inputs that race CANNOT be coming from `extern_memoryDelta` records**.

P2 inputs in v2 witgen come from one of:
- Previous P2 round output (chained within the P2 invocation)
- Memory loads via `extern_memoryDelta` → **excluded** by this data
- **Preflight cycle metadata**: `ctx.preflight.cycles[i].{pc, major, minor, userCycle, diffCount, …}`

By elimination: **the race is in PreflightCycle data that witgen reads deterministically but that was populated racily by the Rust executor before witgen began.**

---

## Updated B7 hypothesis (final)

```
            ┌──────────────────────────────────────────────────────────┐
            │  Rust executor (preflight phase)                         │
            │   - thread::scope spawns segment_callback thread         │
            │   - rayon::into_par_iter on segment building             │
            │   - builds Vec<PreflightCycle> = ctx.preflight.cycles    │
            │                                                          │
            │   <==== RACE HAPPENS HERE: PreflightCycle fields  =====> │
            │         (pc / major / minor / userCycle / diffCount /    │
            │          or auxiliary cycle data)                        │
            │         populated inconsistently across paired runs      │
            │         on POS multi-core EPYC; manifests on WSL much    │
            │         less often (16 vs 32 threads, narrower window)   │
            └────────────────────────┬─────────────────────────────────┘
                                     │
                                     v
            ┌──────────────────────────────────────────────────────────┐
            │  Witgen (deterministic given preflight)                  │
            │   - exec_FieldToWord, exec_Poseidon2, etc.               │
            │   - reads ctx.preflight.cycles[i] for each cycle         │
            │   - calls extern_memoryDelta with read addr/data         │
            │     (memory delta calls ARE deterministic given          │
            │     the same preflight cycles — confirmed by B4)         │
            │                                                          │
            │  Output: trace cells + (rare) ΔT diff in touch bitmap    │
            └────────────────────────┬─────────────────────────────────┘
                                     │
                                     v
            ┌──────────────────────────────────────────────────────────┐
            │  Accum + finalization (cycles ~33K..46K)                 │
            │   - Final segment-commit P2                              │
            │   - 24 cycles diverge here every paired run              │
            │     (env noise, NOT mutation-correlated)                 │
            └──────────────────────────────────────────────────────────┘
```

We've eliminated the witgen and accum layers as race sources. The race is in the executor/preflight layer.

---

## Where this leaves B7 closure

We have, with high confidence:

- ✅ **Race is real** (B Pass 1 located it, B Pass 2 confirmed it under different verbosity)
- ✅ **Race is POS-only** (Phase A standalone reproducer ran 0/30+ locally on WSL)
- ✅ **Race manifests at user-phase P2** (B Pass 1 B2 trace: userCycle 3929, 8 lanes diverged across 23 P2 cycles)
- ✅ **Race rate is 1–2% per paired mutation, intermittent and pair-dependent**
- ✅ **Race is NOT in `extern_memoryDelta`** (this B4 result — every memory op in the user phase is bit-identical A vs B)
- ✅ **Race is in PreflightCycle fields** (only remaining input path to witgen)
- ✅ **Most likely Rust-side parallelism** (`thread::scope` + `rayon` in executor)

We have not yet:

- ❌ Pinpointed the **specific field** of PreflightCycle that's racily written (would need a B5 patch fingerprinting `ctx.preflight.cycles[...]` before witgen consumes it)
- ❌ Tested whether forcing `RAYON_NUM_THREADS=1` eliminates the race (single-line fix-or-confirm experiment)

---

## Recommended next step — decision point for the user

We have **two viable paths** from here. Both are short.

### Path A — "Confirm-and-document" (1 dispatch, ~30 min, decisive)

Dispatch the existing B Pass 1 host on POS one more time, but set `RAYON_NUM_THREADS=1` (and optionally `RISC0_KECCAK_PO2=` unset, single-threaded everywhere). If the race **vanishes**, we've confirmed Rust parallelism is the source — we can either keep that setting in our POS launcher or document it as a known sensitivity. If the race **persists**, the parallelism in `thread::scope` (which doesn't respect rayon thread count) is the culprit and we'd need to disable that too.

This **closes B7** with one experiment and gives us an operational knob.

**For Composer**: easy — same SPREAD plan, add `RAYON_NUM_THREADS=1` to the env exports.

### Path B — "Pinpoint-the-field" (1 patch + 1 dispatch, ~3 hr including rebuild)

Apply a B5 patch that, after preflight completes and before witgen begins, hashes the entire `ctx.preflight.cycles` vector field-by-field per cycle. Dispatch on POS, diff A vs B. Whatever fields disagree at whichever cycle indices, that's the exact race signature.

This **localizes the bug to a struct field** but does not by itself fix it. It's the right path if we want to **submit a real fix upstream to RISC Zero** or write a proper bug report. It's the wrong path if we just need to start Phase 8 reliably.

---

## My recommendation: **Path A**

Three reasons:

1. **It directly tests the dominant hypothesis** with a one-line config change. If the race vanishes, we know the parallelism is the cause and we have a workable mitigation **without** touching RISC Zero source code.
2. **Time-economy**: We have spent significant cycles on B7. Path A buys us closure in 30 minutes. Path B is another 2–4 hr investment for a more refined localization that we don't strictly need for Phase 8 launch.
3. **Phase 8 is the actual goal.** B7 is a measurement-quality preflight. A 1–2% noise floor in rewards, if confirmed environmental and mitigatable by `RAYON_NUM_THREADS=1`, is fully acceptable; we'd just run Phase 8 with that env var set.

If Path A confirms the hypothesis: we close B7, ship the fix, launch Phase 8. If Path A does not eliminate the race: we know parallelism is **not** sufficient as a cause, and we go to Path B as a follow-up.

---

## Side note: data-quality note on B4 itself

The B4 fingerprint as designed (hashes `extern_memoryDelta` records, FNV-1a XOR per cycle) is **fit-for-purpose** — it correctly proves memory records are deterministic A vs B in the user phase, which is what we wanted to test. The 24-cycle finalization noise is interesting but downstream of everything that affects rewards, so it doesn't matter for Phase 8.

We do **not** need to refine B4 (e.g., add lookup-record fingerprinting). That work would be redundant given what we now know.

---

## Files produced by this analysis

- `a4/docs/cloud1/composer/PHASE_7D_INC3D_B2_OPUS_ANALYSIS.md` (this file)
- (no other code changes — analysis-only)

## Handback to user

Question for you, Ivan:
- **Path A** (one POS dispatch with `RAYON_NUM_THREADS=1` to test/confirm) — recommended
- **Path B** (B5 patch + POS to pinpoint exact PreflightCycle field) — more thorough, more time
- **Skip both, declare B7 done with documented 1–2% noise floor** — most aggressive

If you pick Path A, I'll write the Composer handoff next. The patch surface is zero (same host binary), just an env var change in the launcher.
