# D1.B — CGC Coarsening Variants: Implementation Spec

**Parent plan:** `IV_POS_8_PRELIMINARY_PLAN.md` §3 D1.B + `IV_POS_8_D1_REVISIT_PLAN.md` §3.1 + §3.1.1
**Pro reference:** `ProG_Report_3.md` §11 (CGC reward sketch) + Pro's "maybe page_class, not raw/log2 bucket" hint
**Status:** **v0.4.3 — Batch 1 ACCEPTED 2026-06-17 15:30 EDT; Batch 1.6 IMPLEMENTED ~18:00 EDT (review pending); Batch 1.5 IMPLEMENTED ~18:30 EDT (gate-passing); Batch 1.5b §3.2.4 reframed as ENHANCEMENT (not bug fix) per Composer review pushback P1 — Batch 1.5 was spec-correct under v0.4.1 §0.4; 1.5b promotes implicit `user_other` catch-all to explicit `user_dynamic` for Pro-disclosure clarity. v0.4.3 corrections (Opus errors caught by Composer): (P3) §1.2 hex addresses were wrong (`0x0021A2F8` was inside `.rodata`, not at boundary; correct is `0x00219DB8`) — §1.2 now defers to JSON artifact entirely, no hand-typed hex. (P4/P5) Page_class first-hit COUNT is unchanged by 1.5b (1:1 label swap `user_other → user_dynamic`); §3.3 invariant reverted from `≈ 14-16` to `≈ 13-15` (Opus speculation removed). (P2) Audit count corrected from Opus's ad-hoc 3327 to Composer's canonical 4850 hits / 4326 distinct via `cat_a_db_list()`. `user_dynamic` upper bound is `0xBFFF0000` (D8 user-band boundary), not `0xC0000000` (GUEST_MAX_MEM); avoids overlapping with `user_bigint` Q-PC-3 pass-through.** v0.4.1 patch over v0.4: (P1) §3.3 task 1 corrected — production_log2_corrected does NOT read stored `compressed_global_coverage.first_hit_mutation_id` directly; instead, ALL 4 variants derive memory keys from corrected replay first-hit map. (P2) §3.3 prerequisite + task 1 + sanity invariants reframed — stored `ctx_json` is buggy-pre-fix and NOT the source for any Batch 2 variant; corrected expectations are `region_only ≈ 9 regions`, `log4 ≈ 30-50 keys`, `page_class ≈ 13-15 keys`. (P3) §3.2.5 housekeeping — `D1B_BATCH1_REPORT.md` amendment is **§9** (after existing §8), NFP-10 is "Opus drafted, Composer verifies". (P4) §3.2.5 task 3 now documents the memory-replay / lookup-snapshot methodology split as load-bearing for patch-invariance proof. v0.4 history below. Batch 1 deliverables green; mid-implementation discovery via Composer's root-cause analysis found that `_coerce_broken_addr` in `compressed_global_extractor.py:216` prefers Hook-3 `addr` (word index) over `byte_addr` (VM byte address), mis-labeling ~59% of memory contexts (verified by Opus independent SQL: V5 s1234: 58.9%, V1 s1234: 53.2%, decayexp s1234: 55.7%). All R2 V1-V5 + D1.A CGC tables affected. Batch 1.6 lands the one-line field-priority fix + replay tooling + corrected baseline before Batch 2 starts. v0.4 supersedes v0.3.1's "memory channel dead" framing — the channel was masked by labeling bug AND coarsening choice; corrected post-hoc replay is the new comparison baseline. All Q-PC decisions remain resolved (Q-CORPUS-1, Q-PC-1..4, Q-PC-EHF, Q-BATCH-MODEL). v0.3.1 patch over v0.3 fixed Composer-flagged stale strings (`d1e_handoff_K_window.md` → `d1e_handoff_CGC_saturation.md` in §3.4, "K-window guidance" / "K-choice" wording removed from §2.1 + §3.3 Batch 2 goal, "parsed as int" → `parse_memory_byte_addr` in §3.1 task 1, v0.1 → v0.3.1 in §8 checklist) + first-hit semantics added to §1.3 and §3.3 Batch 2 task 1 (load-bearing comparability fix — production CGC curves use first-hit per ctx_key; page_class must derive equivalent first-hit per coarsened key from `global_failures.MIN(mutation_id)`) + §4 risk wording tightened (ELF-mandatory; do not silently fall back to empirical) + ELF inter-section gaps documented + `coverage_db.py:162-173` comment fixed. v0.3 was the substantive Pro-intent + Composer-ELF-investigation rewrite (see v0.3 history entry below for that pass).
**Author:** Opus
**Branch:** `cloud2`
**D2 sync coupling:** none for D1.B v0.1 implementation; Batch 3 must not touch `compressed_global_extractor.py` while D2.B Batch 1 is in flight (analysis-time recompute only)

---

## 0. Goal recap + open questions Ivan must resolve before Batch 1

### 0.1 Goal

Pro's `ProG_Report_3.md` §11 names a specific bug: in our production CGC (compressed-global-context) pipeline, the `address_region = "user"` band covers `[0x00010000, 0xbfff_0000)` (verified `compressed_global_extractor.py:98`) — a huge slab where the only discriminator becomes `address_bucket = floor(log2(addr))`. That makes the CGC reward signal **geometric** ("different ~64KB bin") rather than **semantic** ("different kind of memory"). Pro asks us to evaluate alternative coarsenings; specifically suggests `region_only`, `log4`, and "**maybe page_class, not raw/log2**".

**D1.B deliverable to Pro** (subsection inside D1 report): a side-by-side evaluation of three CGC coarsening variants on our existing 20-DB decay corpus (10 R2 V5 + 5 D1.A decayexp + 5 D1.A decayepoch), plus a recommendation for which variant should become the **D2-default CGC reward signal** when D2 reaches the design-proposal stage.

**Secondary deliverable to D1.E** (the reward-rewire re-run): each coarsening's empirical **CGC saturation profile** on the existing corpus. This informs the **D2 reward CGC choice**, NOT `ExponentialDecayFloor.K` — see §0.1.1 below for why those are different signals.

#### 0.1.1 Pro's two-layer design — K decays on local; CGC + bug-proximity feed adaptive learning

Pro §7 literally writes:

```
Exponential decay: floor_fraction(t) = max(0.20, 0.55 × exp(-local_coverage_seen / K))
```

— so the floor driver is **`local_coverage_seen`** (legacy local constraint discoveries) **by Pro's explicit design**, not CGC or bug-proximity. Verified in production: `ExponentialDecayFloor.current()` at `bandit_ts.py:98-100` reads `local_discoveries`, which is populated from `_sync_local_coverage_after_failures` (`fuzzer.py:652-660`) reading new rows from the legacy `coverage` table.

**Pro's intent** (confirmed in Ivan + Opus + Composer audit, 2026-06-17):

1. Floor decays based on **local survey progress** — once we've seen most local constraint_locs, exploitation should take over from exploration. ← driver = `_local_discoveries`. K stays anchored here.
2. Once floor decays, adaptive TS dominates arm selection. ← driver = `bandit_success` posteriors.
3. **For adaptive mode to be useful**, `bandit_success` must NOT have saturated by the time the floor decays. ← this is where D1.B and D1.C come in.

D1.A's empirical failure (Findings D/E/F): by the time `_local_discoveries` saturated (~46), the existing `bandit_success` signal (`l_new + g_new + s_new`) had also saturated — adaptive mode had no discriminating signal left. **The fix is to make `bandit_success` discriminate longer**, NOT to change what K decays on.

| Saturation curve | Driver | Used for | Who characterizes it |
|---|---|---|---|
| **Floor decay** (`ExponentialDecayFloor.K`) | `_local_discoveries` = cumulative legacy `coverage` table row count | When does the floor decay finish | **D1.E spec** — short SQL pass (`SELECT COUNT(*) FROM coverage` cumulative). Cheap; not a D1.B deliverable. K stays anchored here per Pro §7. |
| **TS Bernoulli learning** | `bandit_success` OR-rate over pulls (L0 coarsening + L1 added channels) | Whether adaptive mode has signal to differentiate arms after the floor decays | **D1.B** (CGC variants; this spec) + **D1.C** (per-mutation bug-proximity signals) + D1.E counterfactual replay |
| **D2 reward CGC default** | `g_new` uniqueness under each coarsening (production log2 vs region_only vs log4_explicit vs page_class) | D2 default CGC reward choice | **D1.B** (this spec) |

**Implication for D1.B's deliverables:**
- D1.B's CGC saturation profile feeds **TS Bernoulli learning** (L0 path in D1.E) and the **D2 default CGC reward choice**. It does **not** feed K.
- D1.B's Batch 3 hand-off note is named `d1e_handoff_CGC_saturation.md`, scoped to those two purposes. K guidance lives entirely in D1.E spec.
- The `L_floor` option I floated in an earlier draft (driving floor from CGC instead of local survey) is **anti-Pro**: it would prevent the floor from ever decaying on local saturation, defeating Pro's whole staged-exploration design. **Removed from scope.** If Ivan ever wants to revisit floor-driver architecture, it's a separate D-level deliverable, not a D1.E option.

### 0.2 Open questions Ivan must resolve before Batch 2

These are **Batch-1-blocking** for `page_class` only; Batch 1 ships region_only + log4_explicit without touching them.

| ID | Question | Why it matters | Recommendation (default if Ivan doesn't pick) |
|---|---|---|---|
| **Q-PC-1** | What is `page_class` semantically? | Three live readings (per Composer/Ivan analysis 2026-06-17): (a) **semantic memory-use class** (`{code, heap, stack, data, host_ecall, user_other}`) from guest layout — Pro-aligned per Report-2 §5; (b) **coarser geometric page index** (e.g. 4KB page id, log4 instead of log2) — weaker Pro fit but trivially computable; (c) "region + access pattern" — original prelim gloss, **rejected** because it duplicates `txn_role` | **(a) semantic memory-use class** — best match to Pro §11 complaint, but it requires guest-binary-aware ranges (see Q-PC-2) |
| **Q-PC-2** | Where do `page_class` boundaries come from? | **Resolved by Composer audit 2026-06-17.** Guest ELF is verified present at canonical path `workspace/output/target/riscv-guest/risc0-methods/risc0-guest/riscv32im-risc0-zkvm-elf/release/risc0-guest` (`readelf -S` parseable). zkVM constants verified in `workspace/risc0-modified/risc0/zkvm/platform/src/memory.rs` (`STACK_TOP`, `TEXT_START`, `GUEST_MAX_MEM`). HOST_ECALL verified in GLOSSARY/D42. Earlier draft cited 3 fallback options because Opus didn't initially know the ELF path. | **ELF MANDATORY** + `memory.rs` constants + GLOSSARY HOST_ECALL. Empirical histograms = validation-only gate (`user_other` ≤ 15%); do NOT derive layout. **Batch 1.5 hard-fails if GUEST_ELF missing** — runs `cargo build --release` instruction, does NOT silently fall back to empirical. Earlier "folklore" ranges (`heap [0x10000000,…)`, `stack [0x70000000, 0x80000000)`, `code [0x00200000, 0x00400000)` slab) are explicitly REJECTED — see §0.4 for provenance audit. `USER_PC_RANGE` in `semantic_zones.py:12` is a **PC band**, NOT memory layout; do not use it as page_class anchor. |
| **Q-PC-3** | Should `page_class` apply to all `address_region` values or only `user` / `user_bigint`? | Pro's complaint is specifically about the `user` band collapse. Splitting `kernel` or `machine_regs` etc. into page_class values may add noise without information. | **Only split `user` and `user_bigint`**; for all other regions, set `page_class = address_region` (i.e., pass-through). This keeps page_class additive within the bulk band, semantically clean elsewhere. |
| **Q-PC-4** | Disclose to Pro? | Pro asked "maybe page_class" — they did NOT specify the definition. Our pick is a substantive substitution that needs Pro buy-in. | **Yes, disclose explicitly** in D1.B subsection + final D1 report. Quote our page_class layout map verbatim. Ask Pro to confirm/correct in their R3 feedback. Same disclosure protocol as the existing log4 → page_class substitution disclosure already mentioned in `IV_POS_8_PRELIMINARY_PLAN.md` §3 D1.B. |

### 0.3 Recommended Ivan-greenlight on Q-PC questions

| Q | Recommended answer |
|---|---|
| Q-PC-1 | Reading (a): semantic memory-use class |
| Q-PC-2 | **ELF MANDATORY** (verified present at canonical path); empirical histograms = validation only (`user_other` % gate) — see §0.4 |
| Q-PC-3 | Apply only to `user` + `user_bigint`; pass-through elsewhere |
| Q-PC-4 | Yes, disclose explicitly |

**If Ivan greenlights the recommended set above**, Batch 1 proceeds without delay (it doesn't touch page_class). If Ivan wants different answers, the only batch this changes is Batch 1.5.

### 0.4 What we now know about `page_class` provenance — folklore vs facts

The "code at `[0x00200000, 0x00400000)` / heap at `[0x10000000, …)` / stack at `[0x70000000, 0x80000000)`" ranges that earlier drafts cited are **folklore**, NOT platform constants. Provenance audit (Composer + Opus 2026-06-17):

| Source | What it actually defines | Reliability for `page_class` |
|---|---|---|
| `risc0/circuit/rv32im/src/execute/platform.rs` | Circuit / executor VM bands: `USER_START = 0x00010000`, `USER_END = 0xC0000000`, kernel, machine_regs, ECALL dispatch, etc. **Does NOT define code/heap/stack within `user`.** | Authoritative for `address_region` (already done). NOT a `page_class` source. |
| **`risc0/zkvm/platform/src/memory.rs`** (verified: `workspace/risc0-modified/risc0/zkvm/platform/src/memory.rs`) | zkVM guest runtime model: `STACK_TOP = 0x00200400`, `TEXT_START = 0x00200800`, `GUEST_MIN_MEM = 0x00004000`, `GUEST_MAX_MEM = 0xC0000000`. Heap is bump-allocated from ELF `_end` up to `GUEST_MAX_MEM`. | **Authoritative for guest-agnostic constants** (stack/text anchors, heap upper bound, zero page) |
| **Guest ELF** (verified: `workspace/output/target/riscv-guest/risc0-methods/risc0-guest/riscv32im-risc0-zkvm-elf/release/risc0-guest` — present, 248292 bytes, `readelf -S` parseable) | Guest-specific: `.text` `[0x00200800, 0x00218db4)`, `.rodata` `[0x00219db8, 0x0021d744)`, `.eh_frame` `[0x0021d744, 0x0022033c)`, `.data` `[0x0022133c, 0x00221394)`, `.bss` `[0x00221398, 0x00221488)`, `_end = 0x00221488` | **Authoritative for guest-specific section ranges** (changes per guest binary) |
| `GLOSSARY` / D42 (`CLOUD1_DECISIONS_FOR_PRO_R2.md:58, 193`) | `HOST_ECALL_ADDR` MMIO buffer at `[0x42000000, 0x42000100)` | Authoritative for the host-comm buffer (this host binary) |
| `semantic_zones.py:12` `USER_PC_RANGE = (0x00200000, 0x00400000)` | **PC classification band** used by `pc_in_user(pc)` (`semantic_zones.py:114-116`) — "is this decode step's PC in user code?" | NOT a memory-address-layout source. ~90% of decode PCs land in this band empirically, but it's a 2 MB *PC slab*, not a 136 KB ELF `.text` section. **Do NOT use as page_class anchor.** |
| `PHASE_3_GLOBAL_CTX.md:72-73` `(0x10000000, 0x70000000, "heap")`, `(0x70000000, 0x80000000, "stack")` | **Phase-3 paper sketch** before extractor code existed — `CLOUD1_DECISIONS_FOR_PRO_R2.md:182` explicitly labels this "a paper sketch ... that guessed at image/heap/stack/user ranges" | **Folklore.** Replaced by `_ADDRESS_REGION_MAP` (one fat `user` band). Never shipped in production. Do NOT use. |
| `CLOUD1_DECISIONS_FOR_PRO_R2.md:191-192` D8 coarseness table "User data / heap `[0x10000000, ~)`", "User stack `[0x70000000, 0x80000000)`" | Carryover folklore — `CLOUD1_DECISIONS_FOR_PRO_R2.md:430` G3 admits "NOT yet verified against the real sha2-host binary's linker layout" | **Folklore.** Disregard for sha2-host page_class. |

**For sha2-host (the inspected guest), the verified layout is:**

| page_class | Range | Source |
|---|---|---|
| `stack` | `[0x00010000, 0x00200800)` | `memory.rs` `STACK_TOP = 0x00200400` (stack grows down from here into the band below TEXT_START) |
| `text` | `[0x00200800, 0x00218db4)` | ELF `.text` section, size `0x0185b4` |
| `rodata` | `[0x00219db8, 0x0021d744)` | ELF `.rodata` (Batch 1.5 decides whether to fold `.eh_frame` `[0x0021d744, 0x0022033c)` into rodata or split) |
| `data_bss` | `[0x0022133c, 0x00221488)` | ELF `.data` + `.bss`, ending at `_end` |
| `heap` | `[0x00221488, 0x42000000)` | `_end` up to HOST_ECALL boundary |
| `host_ecall` | `[0x42000000, 0x42000100)` | GLOSSARY / D42 |
| `user_other` | remainder in `user` band (`[0x42000100, 0xBFFF0000)` minus the above) | Should be small; empirical validation in Batch 1.5 |

`zero_page = [0x00000000, 0x00010000)` and all non-`user`/`user_bigint` regions are **pass-through** per Q-PC-3 (i.e., page_class = address_region for those addresses). `user_bigint = [0xBFFF0000, 0xC0000000)` is pass-through too pending Batch 1.5 empirical check (one semantic class — accelerator I/O).

**Known small gaps** (alignment padding between ELF sections; expected to have zero or trivial hits — Batch 1.5 confirms via empirical check):
- `[0x00200400, 0x00200800)` (1024 B) between `STACK_TOP` and `TEXT_START` → folded into `stack`
- `[0x00218db4, 0x00219db8)` (1028 B) between `.text` end and `.rodata` start → folded into `text` (i.e., `text` row above is more naturally specified as `[TEXT_START, .rodata.addr)` rather than `[TEXT_START, TEXT_START + .text.size)`; Batch 1.5 uses the `[.rodata.addr, .data.addr)` convention shown for rodata to make these gaps disappear into the adjacent class)
- `[0x00221394, 0x00221398)` (4 B) between `.data` end and `.bss` start → folded into `data_bss` (`data_bss` row is `[.data.addr, _end)`)

Batch 1.5 implementation MUST use the half-open-up-to-next-section convention to avoid gap labels. Explicit instruction in §3.2 task 4.

---

## 1. Code architecture — what changes, where

### 1.1 Current state (verified from source)

| Symbol | Location | Current state |
|---|---|---|
| `_ADDRESS_REGION_MAP` | `a4/standalone/compressed_global_extractor.py:96-106` | **9-entry list** of `(lo, hi, label)` + `"invalid"` fallback for addresses outside all ranges. `user` = `[0x00010000, 0xbfff_0000)`. Production source of truth for `address_region`. |
| `address_region(addr)` | `compressed_global_extractor.py:109-122` | Returns label per `_ADDRESS_REGION_MAP`; falls back to `"invalid"` |
| `address_bucket(addr)` | `compressed_global_extractor.py:125-136` | `floor(log2(max(addr, 1)))`, range 0..31 for 32-bit addresses. Production source of `address_bucket`. |
| `compressed_global_coverage` table | `coverage_db.py:395-406` | Stores `ctx_key`, `ctx_json` ({`address_region`, `address_bucket`}), `family`, `first_hit_mutation_id`, `hit_count` |
| `global_failures` table | `coverage_db.py:165-173` | Stores `(mutation_id, family, address)` — **raw address as TEXT**; unique per `(mutation_id, family, address)` |
| `analysis/metrics.py:compressed_global_context_final` | `runs/iv_pos_7/analysis/metrics.py:137-139` | `SELECT COUNT(*) FROM compressed_global_coverage` — counts unique production-bucketed ctx_keys |
| `USER_PC_RANGE` | `a4/standalone/semantic_zones.py:12, 114-116` | `(0x00200000, 0x00400000)` — **PC classification band** used by `pc_in_user(pc)` to label decode-step zones. **NOT** a memory-address-layout source; do NOT use as page_class anchor. ELF `.text` is at `[0x00200800, 0x00218db4)`, a 136 KB section, not a 2 MB slab. |
| Guest ELF | `workspace/output/target/riscv-guest/risc0-methods/risc0-guest/riscv32im-risc0-zkvm-elf/release/risc0-guest` — verified present (248292 bytes, Jun 3 2026), `readelf -S` parseable. Embedded .bin at `risc0-guest.bin` (257 KB) | **Authoritative for `.text`/`.rodata`/`.eh_frame`/`.data`/`.bss` + `_end` ranges**. Cursorignore note: `**/target/` is blocked for Read tool (per `a4/docs/CURSOR_IGNORE.md`); Composer accesses via shell `readelf` and commits a derived JSON artifact under `a4/runs/iv_pos_8/d1b/` (see §3.2) |
| `memory.rs` | `workspace/risc0-modified/risc0/zkvm/platform/src/memory.rs` | Authoritative zkVM guest runtime constants: `STACK_TOP = 0x00200400`, `TEXT_START = 0x00200800`, `GUEST_MIN_MEM = 0x00004000`, `GUEST_MAX_MEM = 0xC0000000`. Stack grows DOWN from `STACK_TOP`; heap bump-allocated from ELF `_end` upward. **Important:** real Hook 3 memory addresses in the `user` D8 band (`[0x00010000, 0xBFFF0000)`) extend above `HOST_ECALL_HI` (0x42000100) all the way to the D8 `user`/`user_bigint` boundary (`0xBFFF0000`) — see §1.2 `user_dynamic` label and Batch 1.5b layout enhancement. These addresses are NOT covered by the "heap" range (which is anchored at ELF `_end` up to HOST_ECALL_LO); they are a mix of mmap-scatter heap, mutation-induced addresses, and dynamic runtime regions for which we have no ELF source. Empirical Composer Batch 1.5 audit on 30 canonical DBs (`cat_a_db_list()`): **4850 hits / 4326 distinct byte_addrs** of user-band traffic fell in this upper-band region — 100% of the `user_other` residual. |
| HOST_ECALL_ADDR | `CLOUD1_DECISIONS_FOR_PRO_R2.md:58 (D42), :193 (D8 table)` | MMIO buffer at `[0x42000000, 0x42000100)`; observed-in-traces source; landed inside the `user` band of `_ADDRESS_REGION_MAP` today |
| `global_failures.address` actual format | Direct SQL inspection of `a4/runs/iv_pos_8/d1a/dbs/*.db` | **Python dict-string** (NOT decimal/hex). Memory family: `"{'addr': 0, 'byte_addr': 0, 'type': 'data', 'wrote': '0x00000000', 'expected': None, 'mismatch_cycle': 1}"`. Cycle family: `"{'index': 0, 'plus': 2253, 'minus': 1}"`. **`byte_addr` is the field to use for memory-family page_class derivation.** Parse with `ast.literal_eval()`, not `int()` |
| `ctx_json` actual content | Direct SQL inspection of `a4/runs/iv_pos_8/d1a/dbs/*.db` | Richer than v0.1 spec said: includes `cycle_phase` and `txn_role` for memory rows (example: `{"address_bucket": 29, "address_region": "user", "cycle_phase": "normal", "family": "memory", "txn_role": "register"}`). Lookup rows have `lookup_index_bucket`, `producer_kind`, `opcode_class` instead of address fields |

### 1.2 New module — `analysis/cgc_variants.py`

Lives at `a4/runs/iv_pos_7/analysis/cgc_variants.py` (analysis-time module; **does NOT** touch production `compressed_global_extractor.py`). Imports the production address-region helper for consistency.

```python
"""D1.B — alternate CGC coarsening functions for post-hoc analysis.

These are analysis-time re-buckets / re-derivations. The production CGC
pipeline is unchanged — D1.B reads stored data and reapplies a different
key derivation, then counts uniques per (family, key).

Per IV_POS_8_D1_B_SPEC.md §0, three variants are evaluated:
  • region_only      — Path 1 (re-bucket from ctx_json)
  • log4_explicit    — Path 1 (re-bucket from ctx_json)
  • page_class       — Path 3 (recompute from global_failures.address dict
                       string → ast.literal_eval → byte_addr)
"""

from __future__ import annotations
import ast
from typing import Iterable, Tuple, Optional
from a4.standalone.compressed_global_extractor import address_region, _ADDRESS_REGION_MAP

# ---------------------------------------------------------------------------
# Helper: parse global_failures.address (Python dict string) → int byte_addr
# ---------------------------------------------------------------------------
def parse_memory_byte_addr(address: str) -> Optional[int]:
    """Memory family stores `{'addr': ..., 'byte_addr': ..., 'type': ..., ...}`
    as a dict string. Extract `byte_addr` as int. Returns None for non-memory
    rows (cycle family stores `{'index': ..., 'plus': ..., 'minus': ...}`).
    """
    try:
        d = ast.literal_eval(address)
    except (ValueError, SyntaxError):
        return None
    ba = d.get("byte_addr")
    return int(ba) if isinstance(ba, int) else None

# ---------------------------------------------------------------------------
# Variant 1: region_only
# ---------------------------------------------------------------------------
def cgc_key_region_only(family: str, ctx_json: dict) -> str:
    """Coarsest variant: (family, address_region). Drops address_bucket.
    For lookup families (no address_region), see hybrid rule §1.5 — production
    ctx_key is used unchanged.
    """
    return f"{family}|{ctx_json.get('address_region', 'unknown')}"

# ---------------------------------------------------------------------------
# Variant 2: log4_explicit
# ---------------------------------------------------------------------------
def cgc_key_log4_explicit(family: str, ctx_json: dict) -> str:
    """Explicit log4 bucketing. STRICTLY COARSER than production log2."""
    bucket_log2 = ctx_json.get("address_bucket", 0)
    bucket_log4 = bucket_log2 // 2
    return f"{family}|{ctx_json.get('address_region', 'unknown')}|log4_{bucket_log4}"

# ---------------------------------------------------------------------------
# Variant 3: page_class  (per Q-PC-1 Reading (a))
# ---------------------------------------------------------------------------
# Semantic memory-use class within `user` / `user_bigint` bands. Layout
# constants are emitted by Batch 1.5 from `readelf -S` on the canonical guest
# ELF + memory.rs constants + GLOSSARY HOST_ECALL. For all other regions,
# page_class is pass-through (== address_region).
#
# NOTE: this is a SCHEMATIC label-set sketch for spec readability ONLY. The
# AUTHORITATIVE numeric values come from Batch 1.5's live `readelf` parse and
# live in `a4/runs/iv_pos_8/d1b/d1b_guest_elf_layout.json`. `cgc_variants.py`
# loads the live layout via `_load_page_class_layout()`; do NOT trust any
# hand-typed addresses in this spec. The earlier v0.4.2 attempt to "correct"
# the draft addresses inline introduced hex-conversion errors (Composer
# Batch 1.5 review push P3); v0.4.3 removes the inline addresses entirely
# and points to the JSON artifact for ground-truth numerics.
#
# Schema (post-Batch-1.5b):
#   stack         in user band, below TEXT_START
#   text          [TEXT_START, .rodata.addr) — folds .text→.rodata gap
#   rodata        [.rodata.addr, .data.addr) — Q-PC-EHF: folds .eh_frame INTO rodata
#   data_bss      [.data.addr, _end) — includes .data + .bss + alignment gap
#   heap          [_end, HOST_ECALL_LO) — bump heap
#   host_ecall    [HOST_ECALL_LO, HOST_ECALL_HI) — GLOSSARY / D42 MMIO carve-out
#   user_dynamic  [HOST_ECALL_HI, D8_USER_HI) — upper user band; mmap-scatter
#                 heap, mutation-induced addrs, dynamic runtime; D8_USER_HI =
#                 0xBFFF0000 (boundary with user_bigint per _ADDRESS_REGION_MAP)
#
# For exact numeric ranges, READ THE JSON ARTIFACT, not this comment.
_PAGE_CLASS_USER_LAYOUT_LABELS = (
    "stack", "text", "rodata", "data_bss", "heap", "host_ecall", "user_dynamic",
)
_PAGE_CLASS_USER_DEFAULT = "user_other"  # post-Batch-1.5b: should be < 0.5% of user-band hits

def page_class(addr: int) -> str:
    region = address_region(addr)
    if region not in ("user", "user_bigint"):
        return region  # pass-through per Q-PC-3
    for lo, hi, label in _PAGE_CLASS_USER_LAYOUT:
        if lo <= addr < hi:
            return label
    return _PAGE_CLASS_USER_DEFAULT

def cgc_key_page_class(family: str, addr: int) -> str:
    """Page-class variant: (family, page_class). Drops address_bucket."""
    return f"{family}|{page_class(addr)}"
```

### 1.3 Re-bucket vs recompute — per-variant data path

| Variant | Path | Data source | Implementation notes |
|---|---|---|---|
| `region_only` | Path 1 (re-bucket) | `compressed_global_coverage.ctx_json` (parse JSON, drop `address_bucket`, GROUP BY `(family, address_region)`) | Trivially equivalent — `(family, region)` already implicit in production keys |
| `log4_explicit` | Path 1 (re-bucket) | Same as above; collapse log2 bucket pairs into log4 buckets | Sanity-check variant — should yield exactly ⌈unique_log2 / pair_collapse_ratio⌉ unique keys |
| `page_class` | Path 3 (recompute) | `global_failures.address` — **Python dict string** per `(mutation_id, family, address)`. Memory rows: `{'addr': N, 'byte_addr': N, 'type': ..., ...}`; cycle rows: `{'index': ..., 'plus': ..., 'minus': ...}`. Extract `byte_addr` for memory family via `ast.literal_eval()` then `d['byte_addr']` (see `parse_memory_byte_addr` in §1.2). | Re-read raw `byte_addr` values, apply `page_class()`. **Two queries, BOTH required for comparability with production:** (a) **Final count** = `COUNT(DISTINCT (family, page_class))` — counts unique coarsened keys ever hit; (b) **First-hit timing per key** = `MIN(mutation_id) GROUP BY (family, page_class(byte_addr))` — required for cumulative curve / AUC / `saturation_cgc_d`. Production CGC curves come from `compressed_global_coverage.first_hit_mutation_id` (one row per first-hit per production ctx_key); for page_class to be comparable, we must derive the equivalent first-hit-per-coarsened-key from `global_failures` (which has many rows per address). **Does NOT depend on `ctx_json`.** |

**Why page_class uses Path 3, not Path 1:** `ctx_json` only stores `{address_region, address_bucket, txn_role, cycle_phase, family}` (verified by direct SQL inspection — see §1.1 row "`ctx_json` actual content") — the raw address is lost in the production pipeline. Re-deriving `page_class` from `address_bucket` is fundamentally lossy (e.g., heap and stack can fall in the same log2 bucket but be different page classes). The raw `byte_addr` from `global_failures.address` is the only sound source. Note that `ctx_json` having `txn_role` / `cycle_phase` is a bonus for future analysis (matches all 5 of Pro's reward fields except `opcode_class` and the proposed `page_class` itself), but D1.B's variants only swap the `address_*` portion — `txn_role` / `cycle_phase` flow through unchanged.

### 1.4 Module integration with `metrics.py`

Add three new metrics functions to `analysis/cgc_variants.py` — each returning an integer count of unique CGC keys per (campaign_id, variant):

```python
def compressed_global_context_final_region_only(conn, campaign_id: int) -> int: ...
def compressed_global_context_final_log4_explicit(conn, campaign_id: int) -> int: ...
def compressed_global_context_final_page_class(conn, campaign_id: int) -> int: ...
```

Existing `compressed_global_context_final` (production log2) is **unchanged** and serves as the baseline.

### 1.5 Hybrid counting rule — memory-family re-bucket + lookup-family pass-through

Verified from `compressed_global_extractor.py:298-320`: the production CGC stores two distinct shapes:

- **Memory family** rows in `compressed_global_coverage` have `ctx_json = {address_region, address_bucket, txn_role, cycle_phase}` (plus structural fields)
- **Lookup families** (`u8`, `u16`, `cycle`) have `ctx_json = {lookup_index_bucket, producer_kind, opcode_class}` — **no `address_region` field**

If a naïve `cgc_key_region_only(family, ctx_json)` is applied to lookup rows, `ctx_json.get('address_region', 'unknown')` returns `'unknown'` and all lookup-family rows collapse to `{family}|unknown` — a single key per family, regardless of `lookup_index_bucket`. That would make D1.B's counts incomparable to the production CGC total (~186) because the total is dominated by memory entries but lookup entries still contribute.

**Hybrid rule** — every counter in §1.4 implements:

```python
def count_cgc_<variant>(conn, campaign_id: int) -> int:
    memory_rows  = SELECT rows from compressed_global_coverage WHERE family='memory'  AND campaign_id=?
    lookup_rows  = SELECT rows from compressed_global_coverage WHERE family IN ('u8','u16','cycle') AND campaign_id=?

    memory_keys  = set of <variant>-recomputed keys from memory_rows (Path 1 or Path 3 as defined in §1.3)
    lookup_keys  = set of production ctx_keys from lookup_rows (UNCHANGED — read straight from compressed_global_coverage.ctx_key)

    return len(memory_keys) + len(lookup_keys)
```

This ensures the count is **comparable to production** total. The variant change is **memory-only**; lookup families are held constant as a baseline.

#### 1.5.1 Sanity invariants — scoped explicitly

| Invariant | Scope | Why |
|---|---|---|
| `region_only_count ≤ log4_explicit_count ≤ production_log2_count` | **Memory-family subset** only (`WHERE family='memory'`) | Re-bucketing only collapses keys; cannot create new ones. Lookup pass-through means the inequality only constrains the memory portion |
| `region_only_total ≤ log4_explicit_total ≤ production_log2_total` | **Hybrid total** (memory re-bucket + lookup pass-through) | Holds because lookup contribution is constant across variants; the memory inequality propagates |
| `page_class_total` order-of-magnitude similar to `region_only_total` | **Hybrid total** | Both are coarse memory bucketings; if page_class is much larger than region_only it likely indicates `_PAGE_CLASS_USER_LAYOUT` is over-subdivided. If page_class is much smaller, layout is under-subdivided |

Batch 1 unit tests validate the memory-subset inequality. Batch 2 sanity invariants validate the hybrid total.

---

## 2. Scope & out-of-scope

### 2.1 In scope

- 3 coarsening functions (`region_only`, `log4_explicit`, `page_class`) shipped as `analysis/cgc_variants.py`.
- Empirical derivation of `page_class` layout map for our inspected guest (Batch 1.5).
- Post-hoc analysis on **20-row decay-comparison corpus** (10 R2 V5 + 5 D1.A decayexp + 5 D1.A decayepoch).
- Paired-test tables, cumulative curves, AUC, per-variant saturation profiles.
- D1.E hand-off note (`d1e_handoff_CGC_saturation.md`): each variant's saturation profile to inform D1.E **L0 rewire** (replace production log2 bucketing) and the D2 default CGC reward choice. **NOT K guidance** — K stays anchored to `_local_discoveries` per Pro §7 (see §0.1.1).
- `d1b_recommendation.md` for D2 reward CGC choice.
- `D1B_SUBSECTION.md` for final D1 report.
- Notebook + HTML.

### 2.2 Out of scope

- **Production-extractor changes** (`compressed_global_extractor.py` edits) — out of scope. D2.B Batch 1 may touch this file for `_TXN_ROLE_BY_KIND`; D1.B stays out of the way.
- **Re-running the fuzzer** — D1.B is analysis-only on existing DBs.
- **CGC for non-memory families** (u8_lookup, u16_lookup, cycle) — current CGC is multi-family but D1.B coarsenings are memory-specific. Other families stay on production bucketing.
- **D1.E reward rewire** — D1.B only characterizes saturation profiles; the rewire decision is D1.E's.

---

## 3. Batched implementation plan

D1.B is broken into **4 batches**. Each batch is a single Composer-pass deliverable with an Opus + Ivan review checkpoint before the next batch starts. Total expected wall: 5–7 days (3–4 days Composer + 2–3 days review).

### 3.1 Batch 1 — Foundation + region_only + log4_explicit

**Goal:** Ship the easy 2-of-3 coarsenings, prove the analysis pipeline, expose any data-source surprises.

**Tasks:**

1. **Data audit** — for each of the 30 DBs in scope for Cat-A analysis (10 R2 V1 + 10 R2 V5 + 10 D1.A decay), report:
   - `compressed_global_coverage` row counts
   - `global_failures` row counts
   - Distribution of `address_region` values
   - Min/max/mean of raw `global_failures.address` for memory family **parsed via `parse_memory_byte_addr()`** (extracts `byte_addr` from the dict-string format — NOT `int(address)`; cycle family has no byte_addr and is skipped per §1.2)
   - Count of memory rows where `parse_memory_byte_addr()` returns None (should be 0; non-zero indicates malformed dict-string)
   - Confirm `ctx_json` is well-formed JSON in every row (and report the actual keyset observed — should match `{family, address_region, address_bucket, cycle_phase, txn_role}` for memory rows per the v0.3 §1.1 audit)
   - Output: `a4/runs/iv_pos_8/d1b/d1b_batch1_data_audit.csv`
2. **Module skeleton** — create `a4/runs/iv_pos_7/analysis/cgc_variants.py` with:
   - `cgc_key_region_only(family, ctx_json) -> str`
   - `cgc_key_log4_explicit(family, ctx_json) -> str`
   - `page_class()` and `cgc_key_page_class()` STUBS that raise `NotImplementedError("populated in Batch 1.5")`
   - Module-level docstring referencing this spec
3. **Counter wrappers** — add 3 counter functions to `analysis/cgc_variants.py`:
   - `count_cgc_region_only(conn, campaign_id) -> int`
   - `count_cgc_log4_explicit(conn, campaign_id) -> int`
   - `count_cgc_page_class(conn, campaign_id) -> int` (raises NotImplementedError until Batch 2)
4. **Unit tests** — `a4/runs/iv_pos_7/analysis/test_cgc_variants.py` (analysis-test convention matches existing `test_metrics.py`, `test_stats.py`, etc. at `a4/runs/iv_pos_7/analysis/`):
   - Each coarsening produces strictly fewer-or-equal unique keys than production (`region_only` ≤ `log4_explicit` ≤ production_log2)
   - `region_only` collapses all log2 buckets within a region to 1 entry
   - `log4_explicit` halves the bucket count for a given region (modulo rounding)
   - Edge cases: empty `ctx_json`, `address_region = "invalid"`, missing fields
5. **Smoke validation** — pick 1 R2 V5 DB + 1 D1.A decayexp DB, run all 3 counters (page_class STILL stub), print headline numbers. Confirm `region_only ≤ log4_explicit ≤ production`. Output: stdout print + `d1b_batch1_smoke.txt`.

**Exit criteria:**

- All unit tests green.
- Data audit CSV written and consistent across 30 DBs (no unexpected NULL `ctx_json` or missing `global_failures`).
- Smoke validation shows expected inequality (`region_only ≤ log4_explicit ≤ production_log2`).
- Batch 1 Composer report + Opus + Ivan review pass.
- **Ivan resolves Q-PC-1 through Q-PC-4** before Batch 1.5 starts.

### 3.2 Batch 1.5 — `page_class` deterministic layout derivation (ELF mandatory)

**Goal:** Emit the canonical `_PAGE_CLASS_USER_LAYOUT` table via deterministic derivation from the verified guest ELF + zkVM `memory.rs` + GLOSSARY. **Empirical histograms are validation-only** (`user_other` % gate); they do NOT derive layout.

**Cursorignore note:** `**/target/` is blocked for Opus Read-tool access per `a4/docs/CURSOR_IGNORE.md`. Composer accesses the ELF via shell `readelf` (or Python `pyelftools` subprocess) and writes a derived JSON artifact into `a4/runs/iv_pos_8/d1b/` (which IS readable). Opus and other Composer instances read the JSON, not the ELF.

**Tasks (in order):**

1. **Pin canonical guest ELF path + verify presence:**
   ```
   GUEST_ELF = workspace/output/target/riscv-guest/risc0-methods/risc0-guest/riscv32im-risc0-zkvm-elf/release/risc0-guest
   ```
   - Verify `GUEST_ELF` exists and is non-empty via shell `ls -la "$GUEST_ELF"`.
   - **HARD FAIL** if missing — emit instruction `cd workspace/output && cargo build --release` and stop. Do NOT fall back to empirical-only layout (Q-PC-2 default is ELF mandatory).
   - Compute and record `guest_elf_sha256` for provenance.
2. **Parse ELF sections** via `readelf -S "$GUEST_ELF"` (or `pyelftools` `ELFFile.iter_sections()`):
   - Extract `.text`, `.rodata`, `.eh_frame`, `.data`, `.bss` (addr, size, end)
   - Extract symbol `_end` via `readelf -s | grep _end`
   - Validate that `.text` starts at `memory.rs::TEXT_START` (0x00200800); abort if not (would indicate guest is built with different layout)
3. **Read `memory.rs` constants** by parsing `workspace/risc0-modified/risc0/zkvm/platform/src/memory.rs`:
   - `STACK_TOP`, `TEXT_START`, `GUEST_MIN_MEM`, `GUEST_MAX_MEM`
   - Validate equality with hardcoded expectations (`STACK_TOP=0x00200400`, etc.); abort if changed (would indicate zkVM model shift)
4. **Construct `_PAGE_CLASS_USER_LAYOUT`** from §0.4's expected output:
   ```
   stack       = [0x00010000, TEXT_START)              # below TEXT_START in user band
   text        = [TEXT_START, TEXT_START + .text.size)
   rodata      = [.rodata.addr, .data.addr)            # includes .eh_frame; see Open Q-PC-EHF below
   data_bss   = [.data.addr, _end)
   heap        = [_end, 0x42000000)
   host_ecall  = [0x42000000, 0x42000100)              # GLOSSARY / D42
   ```
   - **Q-PC-EHF (new, Batch-1.5-time decision):** fold `.eh_frame` into `rodata` (single read-only-data class) or split as its own `eh_frame` page_class? Default: **fold** — `.eh_frame` is read-only unwind metadata semantically adjacent to rodata; splitting adds a class with few hits. Document the choice in `d1b_page_class_layout.json`.
5. **Empirical validation** (gate, NOT derivation):
   - Aggregate raw `byte_addr` values in `user` / `user_bigint` region across all 30 audited DBs (using `parse_memory_byte_addr` from §1.2)
   - Compute fraction of addresses falling in each label
   - **Gate:** `user_other` fraction MUST be ≤ 15%. If exceeded, log all `user_other` addresses + histograms (4KB granularity) and stop for Ivan review (likely indicates a guest-specific subregion not covered by `.text`/`.rodata`/`.data`/`.bss`/`.heap` — e.g., bigint scratch, custom memory pool)
   - **Sanity:** validate that no `user`/`user_bigint` address falls in `[STACK_TOP, TEXT_START)` (the 1 KB stack-text gap) — if it does, refine the `stack` boundary
6. **Write artifacts** to `a4/runs/iv_pos_8/d1b/`:
   - `d1b_guest_elf_layout.json`: machine-readable provenance (ELF sha256, section addrs/sizes, memory.rs constants, derivation timestamp, Composer version)
   - `d1b_page_class_layout.md`: human-readable derivation report + final table + `user_other` fraction + histogram visualization (matplotlib PNG) + Pro-disclosure draft (§Q-PC-4 protocol)
7. **Implement `page_class()` and `cgc_key_page_class()`** in `cgc_variants.py`, removing the `NotImplementedError` stub. Update `_PAGE_CLASS_USER_LAYOUT` with the derived values (which should match the §1.2 draft modulo Q-PC-EHF).
8. **Unit tests** in `a4/runs/iv_pos_7/analysis/test_cgc_variants.py`:
   - Each ELF-derived range maps to its expected label (test cases drawn from `d1b_guest_elf_layout.json`)
   - `user_other` returned for addresses inside `user` but outside any sublabel
   - Pass-through for `address_region != "user"` and `!= "user_bigint"` (kernel, machine_regs, etc.)
   - Cross-region addresses don't leak labels
   - `parse_memory_byte_addr` handles all observed forms in our DBs (memory dict, cycle dict, malformed)

**Exit criteria:**

- `d1b_guest_elf_layout.json` written with provenance + sha256
- `_PAGE_CLASS_USER_LAYOUT` shipped + reviewed by Ivan + (optionally) Pro for disclosure approval
- `d1b_page_class_layout.md` written
- All page_class unit tests green
- `user_other` fraction ≤ 15% (or documented exception with Ivan sign-off)
- Q-PC-EHF resolved (fold vs split `.eh_frame`)
- Batch 1.5 review checkpoint passed

### 3.2.4 Batch 1.5b — **`user_dynamic` layout enhancement** (post-Batch-1.5 audit-driven enhancement)

**Origin:** Post-Batch-1.5 audit by Opus (2026-06-17) found that **100% of `user_other` residual addresses** (Composer's canonical-30-DB count: 4850 hits / 4326 distinct byte_addrs) fall in `[HOST_ECALL_HI=0x42000100, D8_USER_HI=0xBFFF0000)` — the upper user band above HOST_ECALL. Composer's Batch 1.5 layout passes the `user_other ≤ 15%` gate (3.158% achieved); the empirical residual is structurally concentrated in a single coherent region that §0.4 already explicitly designated as the catch-all bucket. Batch 1.5b renames/promotes this implicit catch-all into an explicit `user_dynamic` label for **Pro-disclosure clarity**.

**Framing (per Composer review pushback P1, 2026-06-17):** Batch 1.5b is an **enhancement**, NOT a bug fix. §0.4 already designed `user_other` as the catch-all for `[0x42000100, 0xBFFF0000)`. Composer's Batch 1.5 implementation correctly applied the spec. Batch 1.5b promotes the implicit `user_other` catch-all to an explicit, named `user_dynamic` class so that Pro can see "every user-band address has a named class" rather than "3% is in `user_other`, what's that?" Per Composer review pushback P4: at the CGC-key level, `cgc_key_page_class = f"{family}|{page_class(addr)}"` is a pure label string, so `user_other → user_dynamic` is a 1:1 label swap that does NOT change page_class first-hit counts. Batch 2 metrics under v0.4.1 (without 1.5b) would still be valid; 1.5b just makes the Pro-facing report cleaner.

**Why `user_dynamic` and not `heap` / `user_high` / `user_runtime`:** We have no ELF evidence for what specifically lives in `[0x42000100, 0xBFFF0000)`. The addresses are scattered across the range (not bump-sequential), consistent with a mix of (a) heap-allocator mmap-scatter for large allocations, (b) RS-field-mutation-induced wild addresses (a real fuzzing artifact at this layer), and (c) other dynamic runtime structures. `user_dynamic` is descriptive ("upper user band, dynamic runtime memory, no ELF source") rather than semantic ("heap" — would overclaim).

**Upper-bound choice — `0xBFFF0000` (NOT `0xC0000000`)** per Composer P-naming alignment: D8 `_ADDRESS_REGION_MAP` defines `user` as `[0x00010000, 0xBFFF0000)`. Addresses in `[0xBFFF0000, 0xC0000000)` are `user_bigint` and pass through per Q-PC-3. Layout upper bound aligns to D8 region boundary, not `GUEST_MAX_MEM`.

**Tasks (Composer, ~30 minutes):**

1. **Extend `_PAGE_CLASS_USER_LAYOUT`** in both `cgc_variants.py` (fallback const) and `build_page_class_layout.py` (derivation builder):
   - Add entry: `(0x42000100, 0xBFFF0000, "user_dynamic")` immediately after the `host_ecall` entry
   - Layout remains half-open + non-overlapping; `0xBFFF0000` upper bound matches D8 `user` band end
2. **Re-run `build_page_class_layout.py`** to re-derive `d1b_guest_elf_layout.json` + `d1b_page_class_layout.md` + histogram PNG with the extended layout. Validate:
   - `user_other` fraction drops from 3.158% to ~0% (target: < 0.5%)
   - `user_dynamic` becomes a populated label in the histogram with ~4850 hits
   - All other label counts unchanged
3. **Update tests** in `test_cgc_variants.py`:
   - Add `test_page_class_user_dynamic_above_host_ecall` — verifies addresses in `[0x42000100, 0xBFFF0000)` get `user_dynamic`
   - Add `test_page_class_user_bigint_unchanged_by_user_dynamic` — verifies `[0xBFFF0000, ...)` still passes through as `user_bigint` (Q-PC-3 preserved)
   - Update `test_page_class_empirical_gate_documented` to assert `user_other < 0.5%` post-extension
4. **Update `D1B_BATCH1_5_REPORT.md`** with §X "Batch 1.5b follow-up" addendum:
   - Audit finding (100% of user_other in upper band)
   - Spec design intent reframing per P1 (Batch 1.5 correctly implemented v0.4.1; this is enhancement)
   - Counts: 4850 hits / 4326 distinct byte_addrs (corrects Opus's earlier ad-hoc 3327; Composer used canonical `cat_a_db_list()`)
   - Patch + re-derivation results
5. **Run `cgc_variants` test suite** to confirm 17+ tests pass (was 15)

**Exit criteria:**

- `d1b_guest_elf_layout.json` updated with `user_dynamic` entry (upper bound `0xBFFF0000`); `user_other_fraction_pct < 0.5`
- `d1b_page_class_layout.md` updated; Pro disclosure draft now says "user_other = 0% (all user-band traffic classified); user_dynamic captures upper-band runtime traffic above HOST_ECALL"
- `cgc_variants.py` extended layout + new tests
- `D1B_BATCH1_5_REPORT.md` addendum landed
- Batch 1.5b is folded into the single D1.B squash commit (Batches 1 + 1.5 + 1.5b + 1.6) per Ivan's "single D1.B commit" preference

**Why this matters for Batch 2 (CORRECTED per Composer review P4/P5):**

- Page_class first-hit COUNT is essentially unchanged: `user_other → user_dynamic` is a 1:1 label swap; same number of distinct page_class keys. The v0.4.2 update of `page_class_memory ≈ 13-15 → 14-16` was speculative; v0.4.3 reverts to `≈ 13-15` (or whatever Batch 2 actually measures).
- Page_class KEY STRINGS change: `memory|user_other` → `memory|user_dynamic`. Pro-facing tables/plots use cleaner labels.
- Batch 2 could technically run on the pre-1.5b layout and produce the same metric counts; Batch 1.5b is for Pro-disclosure hygiene, NOT metric validity.
- Recommendation: still land 1.5b before Batch 2 so the Pro-facing output is clean from the start (avoids needing to swap labels in post-hoc artifacts).

### 3.2.5 Batch 1.6 — **EXTRACTOR FIELD-PRIORITY FIX** (`_coerce_broken_addr` bug)

**Origin:** Mid-implementation discovery by Composer 2026-06-17 (post-Batch-1 acceptance) of a production bug in `a4/standalone/compressed_global_extractor.py:216`. **The Batch 1 audit data triggered the discovery** — when memory `address_region` distributions came back as `{user, zero_page}` only across all 30 DBs despite rich `global_failures` geography, root-cause analysis traced it to the field priority in `_coerce_broken_addr`.

**The bug (one line):**

```python
# CURRENT (broken):
for key in ("addr", "byte_addr", "address"):

# FIX:
for key in ("byte_addr", "addr", "address"):
```

**Why it's a bug (verified by Opus independent SQL 2026-06-17, 13670/13670 invariant + region-mismatch measurement):**

| Field | What it is | Where it should be used |
|---|---|---|
| `addr` | Circuit word address from `A4MemoryRecord` (`ffi.cpp:113`); `addr × 4 = byte_addr` always (13670/13670 verified on V5 s1234) | Hook 3 residue math (`ffi.cpp:553-556`) — correct use |
| `byte_addr` | 32-bit VM byte address, computed by `ffi.cpp:590` specifically for VM region labeling | D8 `address_region()` map (defined on byte addresses per `platform.rs`); ELF page_class derivation — correct use for CGC labeling |

`_coerce_broken_addr` picks `addr` first → `address_region(word_address)` mis-classifies ~55-59% of Hook 3 memory dicts. Stored CGC memory `address_region` collapses to `{user, zero_page}` despite Hook 3 actually seeing `{user, user_regs, kernel, machine_regs, machine_special, ecall_dispatch, user_bigint, zero_page, invalid}` (9 distinct regions, verified V5 s1234).

**`address_bucket` is also affected** — line 305-306 derives both `address_region` and `address_bucket` from the same coerced address. After fix, bucket values shift by +2 (since log2(byte_addr) = log2(addr) + 2); count of distinct buckets stays roughly similar, but bucket *labels* shift.

**Scope verification:**

- ✅ Lookup families (`cycle`, u8, u16): UNAFFECTED — they use `broken_indices` via `_coerce_broken_index` (different function, different fields)
- ✅ Local context / `local_context_final`: UNAFFECTED — derived from `failures` table via constraint_loc strings, no addresses involved
- ✅ Arms / scheduler: UNAFFECTED — semantic arm universe doesn't pass through this extractor
- ❌ Memory CGC keys for all R2 V1-V5 + D1.A decay DBs: AFFECTED — ~59% of contexts mis-labeled

**Tasks (single Composer pass, target 3-4 hours; Batch 1.5 ELF research can proceed in parallel):**

1. **Patch `_coerce_broken_addr` field priority** in `a4/standalone/compressed_global_extractor.py:216` (one-line change). **This is an explicit authorized exception to §2.2 "Composer DOES NOT TOUCH compressed_global_extractor.py"** — granted because Batch 1's audit data is what surfaced the bug and the fix is load-bearing for Batch 2.

2. **Add regression unit tests** in `a4/standalone/tests/test_compressed_global_extractor.py` (file exists; add new tests, do NOT create a new file):
   - **Test A:** Hook 3 dict `{"addr": 0x3FFFC022, "byte_addr": 0xFFFF0088, "type": "register"}` → `_coerce_broken_addr` returns `0xFFFF0088` (not `0x3FFFC022`) → `address_region` is `"user_regs"` (not `"user"`)
   - **Test B:** Hook 3 dict missing `byte_addr` (legacy format) → falls back to `addr` correctly
   - **Test C:** Hook 3 int-only entry (oldest legacy format, no dict) → returns int unchanged via the `isinstance(raw_addr, int)` branch
   - **Test D:** Integration test: replay one mutation from V5 s1234 `hook3_raw` through `extract_compressed_global_contexts` post-patch; assert the resulting memory keys include at least one of `{user_regs, kernel, machine_regs}`
   - **Test E:** Field-priority documentation test (asserts tuple `("byte_addr", "addr", "address")` to prevent regression on future edits)

3. **Write replay tool** `a4/runs/iv_pos_8/d1b/analysis/replay_cgc_corrected.py`:
   - Inputs: a DB path
   - **Memory family:** Re-extract from `hook3_raw.raw_json` via `extract_compressed_global_contexts` (automatic — patched extractor in the imported module). `mutation_major` does NOT affect memory key construction (memory uses `address_region`, `address_bucket`, `txn_role`, `cycle_phase` — none depend on `major`); passing `major=0` is safe for memory replay.
   - **Lookup family:** Take first-hit per unique `compressed_ctx_json` row from `hook3_raw` (runtime snapshot — patch-invariant since lookup uses `_coerce_broken_index`, NOT `_coerce_broken_addr`). Do NOT re-extract lookup through `extract_compressed_global_contexts` — that would create spurious mismatches due to `major`/opcode_class dependence that doesn't reflect the field-priority patch. Replay-vs-stored lookup match must be 0 mismatches across all 30 DBs (sanity invariant).
   - Build first-hit map `{ctx_key → first_hit_mutation_id}` merging memory (replay) and lookup (hook3_raw snapshot)
   - Compare to stored `compressed_global_coverage` (the pre-fix snapshot, kept for audit)
   - Outputs: side-by-side comparison rows (production-buggy vs replay-corrected: total keys, per-family counts, per-region distribution)
   - **Read-only on input DBs** — outputs go to `a4/runs/iv_pos_8/d1b/replay_artifacts/`
   - **Methodology note**: This memory-replay / lookup-snapshot split is the load-bearing methodology decision. It preserves patch-invariance for the unaffected channel (sanity check) while applying the patch only where it actually matters (memory labeling). Document this in `D1B_BATCH1_REPORT.md` §9.

4. **Run replay on all 30 audit DBs**, produce `d1b_batch1_replay_corrected.csv` with columns:
   - corpus, variant, seed
   - `prod_buggy_memory_keys`, `prod_corrected_memory_keys`, `delta_memory_keys`, `delta_pct`
   - `prod_buggy_lookup_keys`, `prod_corrected_lookup_keys` (should match; sanity check that lookup is unaffected)
   - `prod_buggy_memory_regions_json`, `prod_corrected_memory_regions_json` (counts per region)
   - `prod_buggy_total`, `prod_corrected_total`

5. **Coordinate with D2 team before commit:**
   - The fix touches `a4/standalone/compressed_global_extractor.py` — same file D2.B Batch 1.5e was scheduled to also edit for `_TXN_ROLE_BY_KIND`
   - Notify the D2 Opus/Composer window: "Landing one-line field-priority fix on `_coerce_broken_addr` (`compressed_global_extractor.py:216`). Orthogonal to D2.B's `_TXN_ROLE_BY_KIND` work but same file. Confirm ordering: do D2.B and D1.B Batch 1.6 land sequentially, or as a single coordinated commit?"
   - **Block on D2 acknowledgment before pushing to `cloud2`.**

6. **Run full existing test suite** to confirm no regressions: `pytest a4/standalone/tests/ a4/runs/iv_pos_7/analysis/ -v`

7. **Amend `D1B_BATCH1_REPORT.md`** with new **§9** "Root cause of memory-channel finding (Batch 1.6 follow-up)" — added AFTER the existing §8 "Commands to reproduce" to preserve the Batch 1 exit checklist numbering:
   - Statement of the bug + verification SQL
   - Impact: 55-59% region mis-labeling across 3 audited DBs (with cross-DB verification table from `d1b_batch1_replay_corrected.csv`)
   - The fix (one-line)
   - Replay methodology split (memory re-extract through patched extractor + lookup `hook3_raw` runtime snapshot for patch-invariance proof) + why this is load-bearing
   - Replay table showing before/after key counts per DB (mean memory Δ across 30 DBs)
   - Lookup-family invariance (0/30 mismatches; sanity check passed)
   - Implication for Batch 2: ALL FOUR variants (production_log2_corrected, region_only, log4_explicit, page_class) derive memory keys from corrected replay, NOT from stored `ctx_json` (stored is buggy and only retained for audit/reproducibility)

8. **NFP-10 in `IV_POS_8_NOTES_FOR_PRO.md`** — Opus drafted; **Composer verifies** the technical claims, impact numbers, and Pro-facing language. NFP-10 is **top-priority Pro disclosure** that bundles with the page_class disclosure in the D1.B Pro-facing subsection at Batch 3.

**Exit criteria for Batch 1.6:**

- Patch landed; 5 new unit tests A-E green + 80 pre-existing tests in `test_compressed_global_extractor.py` still green (85 total); no regressions in full `a4/standalone/tests/` suite (515 passed, 7 skipped) or `a4/runs/iv_pos_7/analysis/` suite (45 passed)
- D2 team acknowledged + ordering agreed
- 30-DB replay CSV written + sha256 recorded
- `D1B_BATCH1_REPORT.md` §9 amendment landed
- `NFP-10` drafted (by Opus) and verified (by Composer) in `NOTES_FOR_PRO.md`
- Squash commit on cloud2: subject `D1.B Batch 1.6: fix _coerce_broken_addr field priority (byte_addr first) + replay tooling + Batch 1 amendment`
- Batch 1.6 review checkpoint passed (Opus + Ivan)

**Why insert this batch instead of folding into Batch 2:**

- Batch 2 metrics need a stable, correct baseline; running Batch 2 on buggy production CGC and then re-running on corrected baseline doubles the Composer work
- The fix is a production-code change with cross-D2 coordination requirements — deserves its own review checkpoint
- Pro disclosure (NFP-10) requires the corrected numbers before drafting; threading the bug discovery and fix into a single batch keeps the narrative coherent
- Batch 1.5 (ELF research) is parallelizable — it doesn't depend on the extractor fix and uses byte_addr by design already

### 3.3 Batch 2 — Full analysis on 20-row decay corpus (uses CORRECTED labeling from Batch 1.6 for ALL variants)

**Goal:** Run all 4 coarsenings (`production_log2_corrected`, `region_only`, `log4_explicit`, `page_class`) on the 20 decay-comparison rows, produce the analysis tables that feed (i) the **D2 default CGC reward choice** and (ii) the **D1.E L0 rewire** (replace production log2 bucketing in `compressed_global_extractor.py` with the recommended coarsening). **Explicitly NOT** the D1.E K-choice — K stays on `_local_discoveries` per Pro §7; D1.E spec characterizes that separately via legacy `coverage` cumulative curves (see §0.1.1).

**Batch 1.6 prerequisite — applies to ALL 4 variants for memory:** Memory keys for `production_log2_corrected`, `region_only`, `log4_explicit`, and `page_class` are ALL derived from the **corrected first-hit map** produced by `replay_cgc_corrected.py` (or its Batch-2-extended counterpart). The stored `compressed_global_coverage.ctx_json` from R2 + D1.A DBs is **buggy-pre-fix** and is preserved for audit/reproducibility but is **NOT** the source for any Batch 2 variant. Lookup keys for all variants come from `hook3_raw.compressed_ctx_json` (patch-invariant runtime snapshot — see Batch 1.6 §3.2.5 task 3 methodology).

**Why this matters (Composer P2, 2026-06-17):** Batch 1's `region_only=2`/`log4≈16` finding was **double-masked** — the bug folded ~59% of memory contexts into `{user, zero_page}` *and* the coarsening was lossy. If Batch 2 fixes only the production baseline but leaves coarsenings on stored ctx_json, the comparison "production_log2_corrected vs region_only" becomes "corrected memory vs buggy-coarsened memory" → meaningless. Corrected memory expects `region_only ≈ 9 distinct regions` (the 9 D8 bands actually present per replay), `log4_explicit ≈ 30-50 keys` (9 regions × ~3-5 log4 buckets per region with sparsity), and `page_class ≈ 13-15 keys` (~7 ELF classes inside user + ~8 pass-through regions). The Batch 2 inequality `region_only ≤ log4_explicit ≤ production_log2_corrected` must hold on corrected labeling, NOT on stored ctx_json.

**Tasks:**

1. **`build_d1b_artifacts.py`** at `a4/runs/iv_pos_8/d1b/analysis/`:
   - Discover the 20 decay-comparison DBs via existing `discover.py`
   - **Pre-compute corrected first-hit maps** for each DB by calling the Batch-1.6 replay machinery (extend `replay_cgc_corrected.py` or import its core functions) to get `corrected_memory_first_hits = {ctx_key → first_hit_mutation_id}` (full corrected memory ctx_json) and `lookup_first_hits = {ctx_key → first_hit_mutation_id}` (from `hook3_raw.compressed_ctx_json`). These two maps are the **single source of truth** for ALL variant computations below. Do NOT read `compressed_global_coverage.ctx_json` for any variant — it's buggy-pre-fix.
   - For each DB and each variant in `{production_log2_corrected, region_only, log4_explicit, page_class}`:
     - **Construct per-(family, coarsened-key) first-hit map** = `MIN(mutation_id)` over the corrected source maps:
       - **`production_log2_corrected`**: directly use `corrected_memory_first_hits ∪ lookup_first_hits` (no coarsening; this IS the corrected production schema)
       - **`region_only`**: re-bucket memory entries → `{(family='memory', address_region): MIN(first_hit_mutation_id)}`, pass-through lookup entries unchanged (hybrid counting rule §1.5). `address_region` is the corrected value (from byte_addr) carried by `corrected_memory_first_hits`.
       - **`log4_explicit`**: re-bucket memory entries → `{(family='memory', address_region, log4_bucket): MIN(first_hit_mutation_id)}`, pass-through lookup. `log4_bucket = floor(log2(byte_addr) / 2)` from the corrected ctx_json's `address_bucket` (which is already `log2(byte_addr)` post-patch; divide by 2 floored).
       - **`page_class`**: derive memory entries → `{(family='memory', page_class(byte_addr)): MIN(first_hit_mutation_id)}` from `parse_memory_byte_addr` over `global_failures` (page_class is computed fresh from byte_addr; does not need replay because `parse_memory_byte_addr` already uses byte_addr by Batch-1 design), pass-through lookup. **First-hit semantics**: `MIN(mutation_id)` per `(family, page_class_key)` over `global_failures` rows, per §1.3.
     - Compute final CGC count = `len(first_hit_map)`
     - Compute cumulative CGC curve = sorted `first_hit_mutation_id` values, binned at 100-step granularity
     - Compute AUC (normalized to [0,1] window)
     - Compute `time_to_X` for X = 10%, 50%, 90% of final count, using the first-hit map
2. **Output CSVs:**
   - `d1b_metrics_table.csv` — per-DB per-variant final count + AUC + time-to-percentile thresholds
   - `d1b_paired_tests.csv` — paired t-tests for V5-static vs decayexp, V5-static vs decayepoch, decayexp vs decayepoch under each variant
   - `d1b_saturation_profile.csv` — per-variant `(saturation_cgc_d, saturation_mutation_id)` pair where the cumulative CGC curve enters its asymptotic regime (defined as: first 100-step bin where < 1 new unique key is added on average across the 5 paired seeds per variant). **Note: this is CGC saturation, NOT `_local_discoveries` saturation — see §0.1.1.**
3. **Notebook** `IV_POS_8_D1B_NOTEBOOK.ipynb`:
   - Headline numbers
   - Per-variant cumulative curves (1 plot per variant, 3 lines for V5/decayexp/decayepoch)
   - Paired-test result tables
   - Saturation-profile summary table
   - Reproducibility section with sha256s
4. **Sanity invariants (all computed on corrected memory labeling, hybrid totals):**
   - For every DB: `region_only_memory ≤ log4_explicit_memory ≤ production_log2_corrected_memory` (memory subset; the coarsening ordering must hold strictly for the channel actually being coarsened)
   - For every DB: `region_only_hybrid ≤ log4_explicit_hybrid ≤ production_log2_corrected_hybrid` (after pass-through lookup add-on; less strict but should hold since lookup cancels)
   - For every DB on memory subset: `region_only_memory ≈ 9` (the 9 D8 regions; some DBs may have fewer if rare regions like `trap_dispatch_and_beyond` are absent). If `region_only_memory ≤ 5` on any DB after correction, escalate — likely indicates corrected replay is also incomplete
   - For every DB on memory subset: `page_class_memory ≈ 13-15` (rough expected order of magnitude — `cgc_key_page_class = f"{family}|{page_class(addr)}"` is a pure-label key, so the COUNT equals the number of distinct page_class labels actually observed in that DB. Pre-Batch-1.5b: labels include `user_other` (single bucket for upper-band traffic). Post-Batch-1.5b: `user_other` is renamed to `user_dynamic` — **same count**, different label string. Estimate is rough until Batch 2 measures it; if `page_class_memory < 6` or `> 25` on any DB, escalate.). **Batch 1.5b can be deferred without invalidating Batch 2 metrics**, but it should ideally land first for cleaner Pro disclosure labels.
   - For every DB: `lookup_keys` IDENTICAL across all 4 variants (lookup is pass-through; this is a definitional invariant)
   - If any invariant fails → escalate (likely bug in coarsening or replay pipeline)

**Exit criteria:**

- All CSVs written + sha256s recorded
- Notebook executed without errors; HTML export written
- All sanity invariants pass
- Batch 2 Composer report + Opus + Ivan review pass

### 3.4 Batch 3 — Recommendation + D1.E hand-off + subsection

**Goal:** Translate Batch 2's numbers into (i) a Pro-facing D2-reward-CGC recommendation and (ii) a D1.E-facing **L0 hand-off note** (`d1e_handoff_CGC_saturation.md`) with per-variant saturation profiles. Explicitly NOT K guidance — K stays on `_local_discoveries` per Pro §7 (see §0.1.1).

**Tasks:**

1. **`d1b_recommendation.md`** — covers:
   - Which variant best discriminates V5-static from decayexp / decayepoch (statistical separation under each variant)
   - Which variant best matches Pro §11's "semantic, not geometric" intent
   - Which variant should D2 use as the reward CGC signal? (Recommendation + 1–2 sentence rationale)
   - Saturation profiles per variant + implications for D1.E **L0** wiring (replace production log2 CGC bucketing with the recommended coarsening so `g_new` discriminates past `_local_discoveries` saturation — see §0.1.1)
2. **D1.E hand-off note** — `a4/runs/iv_pos_8/d1b/d1e_handoff_CGC_saturation.md`:
   - For each variant, the empirical `(saturation_cgc_d, saturation_mutation_id)` from `d1b_saturation_profile.csv`
   - Plain statement: "**D1.B's CGC saturation does NOT drive `ExponentialDecayFloor.K`** — K is driven by `_local_discoveries` (legacy `coverage` row count) per Pro §7 design, characterized in D1.E spec, not here. See §0.1.1 of this spec."
   - Plain statement of role: "D1.B's saturation table feeds (a) D2's default CGC reward choice and (b) D1.E's L0 (replace production log2 bucketing in `compressed_global_extractor.py` with the D1.B-recommended coarsening), so that `g_new` keeps discriminating after `_local_discoveries` saturates and the floor decays as Pro intended."
3. **`D1B_SUBSECTION.md`** at `a4/runs/iv_pos_8/d1b/` — Pro-facing subsection following the same FROZEN-template structure as `D1A_SUBSECTION.md`:
   - TL;DR
   - Method (re-bucket vs recompute paths)
   - Per-variant results
   - Pro disclosure of page_class layout map (full table)
   - Recommendation for D2 reward CGC
   - Limitations (n=5 paired triplets, frozen-DB analysis, post-hoc-only, etc.)
   - Provenance + revision history
4. **Cross-update** to `IV_POS_8_D1_REVISIT_PLAN.md` revision history noting D1.B Stage 1 complete and citing the D1.E hand-off note.

**Exit criteria:**

- `d1b_recommendation.md` reviewed by Ivan + Opus
- `d1e_handoff_CGC_saturation.md` reviewed by Ivan + Opus (NOT `d1e_handoff_K_window.md` — that was the v0.1-v0.2 name; renamed in v0.3 per §0.1.1 — Pro intent is K stays on `_local_discoveries`, this hand-off feeds D1.E L0 + D2 reward CGC choice only)
- `D1B_SUBSECTION.md` reviewed by Ivan + Opus; Pro-disclosure content explicitly approved
- All Batch 3 artifacts committed to `cloud2`
- D1.B is **FROZEN** at this point — Stage 1 of revisit plan complete; Stage 2 (D1.C) spec drafting begins

---

## 4. Risks + mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Guest ELF cannot be located | **Eliminated** — ELF verified present at canonical path by Composer audit 2026-06-17 (`workspace/output/target/.../risc0-guest`, 248292 bytes). Batch 1.5 hard-fails (with `cargo build --release` instruction) rather than silently degrading; no empirical-only fallback path |
| `user_other` fraction > 15% → page_class layout is too sparse | Medium | Iterate Batch 1.5 by **extending the ELF-derived layout** (e.g., sub-split `user_bigint`, check for `0x000884e6` D42 journal-buffer region per `CLOUD1_DECISIONS_FOR_PRO_R2.md:58`, inspect for additional ELF sections like `.eh_frame_hdr`/`.note.*` not covered in v0.3). **Do NOT silently fall back to empirical bucketing** — Q-PC-2 is ELF-mandatory. If extension is structurally unfixable, escalate to Ivan + document as known limitation in subsection. |
| `region_only` collapses too aggressively → 1–3 unique keys per run (useless signal) | Medium-High | If region_only count < 5 across all 20 DBs (memory subset; lookup pass-through means hybrid total floors at ~lookup-family count), document as "too coarse" in recommendation — D2 should NOT pick it. Falls back to log4_explicit or page_class as primary candidates |
| `page_class` produces similar saturation profile to production log2 → no improvement | Medium | Acceptable — D1.B's job is to report this, not to "rescue" page_class. If true, the recommendation honestly says "current production log4 is near-optimal; D2 reward CGC stays log4" |
| Batch 1.5 derivation conflicts with Pro's intended page_class | Low-Medium | Disclosure protocol (Q-PC-4): Pro can correct in R3 feedback; D1.B is presented as our best derivation, not as canonical |
| Composer touches `compressed_global_extractor.py` (violates §2.2 out-of-scope) | Low | Batch 1 acceptance checklist includes "no production-extractor edits" review |
| Paired tests show null for all 3 coarsenings → D1.B "fails to find a winner" | High | This IS a valid outcome (W-R1 in revisit plan §7). Recommendation honestly reports null + flags that decay variants neutral on CGC metrics even with hindsight coarsening — strengthens the Finding-F-style rationale for D1.E being about reward enrichment, not just coarsening |

---

## 5. Test plan

| Test type | Where | What it covers |
|---|---|---|
| Unit | `a4/runs/iv_pos_7/analysis/test_cgc_variants.py` | All 3 coarsening functions, page_class layout map, edge cases (memory-subset inequality enforced) |
| Integration | `a4/runs/iv_pos_8/d1b/analysis/build_d1b_artifacts.py` self-check assertions | Sanity invariants (`region_only ≤ log4_explicit ≤ production_log2`) |
| Smoke | 1 R2 V5 + 1 D1.A decayexp DB, Batch 1 | Pipeline end-to-end before full-corpus run |
| Reproducibility | sha256 of every CSV in Batch 2 | Recorded in notebook + subsection provenance |
| Cross-validation | n/a for v0.1 | Future: re-run analysis from raw DBs and confirm same numbers |

---

## 6. Provenance + dependency on prior work

| Source | What we use | Status |
|---|---|---|
| `analysis/discover.py` | `SELECTOR_TO_VARIANT` mapping (V5, V5-decayexp, V5-decayepoch) | Already updated by Composer in D1.A Batch 2 — re-verified |
| `analysis/metrics.py` | `compressed_global_context_final` (production log2) as baseline | Read-only; D1.B adds parallel functions, doesn't edit |
| `compressed_global_extractor.py` | `address_region()` helper imported into `cgc_variants.py` | Read-only import |
| `coverage_db.py` | `compressed_global_coverage`, `global_failures` schemas | Read-only |
| `D1A_SUBSECTION.md` | Findings A–F context + variant naming | Cross-reference only |
| `IV_POS_8_D1_REVISIT_PLAN.md` v0.2 | Parent plan + §3.1.1 data-source decision | Authoritative |

---

## 7. Open decisions for Ivan (consolidated, gated by what they block)

**All §7 decisions resolved by Ivan 2026-06-17 14:51 EDT.** Tables below preserved as historical record + answer reference for Composer.

### 7.1 Batch-1 greenlight (RESOLVED)

| # | Decision | Ivan's answer (greenlit 2026-06-17) | Was blocking |
|---|---|---|---|
| Q-CORPUS-1 | D1.B corpora scope | **20-row decay paired-test corpus** (10 V5 + 5 decayexp + 5 decayepoch) for paired tables; **30-row Cat-A corpus** (10 V1 + 10 V5 + 10 D1.A decay) for layout validation only. V1 NOT in decay paired tests (different scheduler family). | Batch 1 (data audit scope) + Batch 2 (paired-test scope) |

### 7.2 Batch-1.5 greenlight (RESOLVED)

| # | Decision | Ivan's answer (greenlit 2026-06-17) | Was blocking |
|---|---|---|---|
| Q-PC-1 | page_class semantic meaning | **Reading (a) semantic memory-use class** — `{stack, text, rodata, data_bss, heap, host_ecall, user_other}` | Batch 1.5 |
| Q-PC-2 | page_class boundary sourcing | **ELF MANDATORY** (verified present); empirical = validation-only `user_other` ≤ 15% gate; hard-fail with `cargo build --release` instruction if ELF missing | Batch 1.5 |
| Q-PC-3 | page_class application scope | **Split `user` and `user_bigint` only**; pass-through elsewhere (kernel, machine_regs, etc.) | Batch 1.5 |
| Q-PC-EHF | `.eh_frame` treatment | **Fold into `rodata`** — read-only unwind metadata semantically adjacent to rodata; splitting creates rare class | Batch 1.5 |

### 7.3 Batch-3 greenlight (RESOLVED)

| # | Decision | Ivan's answer (greenlit 2026-06-17) | Was blocking |
|---|---|---|---|
| Q-PC-4 | Pro disclosure | **Yes, explicit** — full `_PAGE_CLASS_USER_LAYOUT` table + derivation recipe + 4 confirmation requests (Q-PC-1/EHF/user_bigint sub-split/ELF recipe) per NFP-7 disclosure protocol | Batch 3 subsection |

### 7.4 Process preference (RESOLVED)

| # | Decision | Ivan's answer (greenlit 2026-06-17) | Notes |
|---|---|---|---|
| Q-BATCH-MODEL | Composer batch scheduling | **Parallel research, serial impl** — Composer ships Batch 1; during Ivan-review-checkpoint #1, Composer parallel-runs Batch 1.5 *research* (ELF readelf + address dump aggregation); strict serial for Batch 1.5 *impl* → Batch 2 → Batch 3 | Composer Batch 1 doesn't touch page_class, so 1 ‖ 1.5-research overlap is technically safe. Strict serial for 1.5-impl onward preserves review-checkpoint discipline. |

**Plan-level decisions** (D1.E naming, D1.B/D1.C ordering, D1.E job count, L-ceiling, sync mechanism, D1.D fate) live in `IV_POS_8_D1_REVISIT_PLAN.md` §6 and **do NOT block any D1.B batch**.

---

## 8. Composer kickoff checklist (Batch 1)

**GREENLIT 2026-06-17 14:51 EDT by Ivan.** Composer is cleared to begin Batch 1 immediately. Checklist:

- [ ] Read `IV_POS_8_D1_B_SPEC.md` **v0.3.1** (this document, head-to-tail) + cited line references in `coverage_db.py` and `compressed_global_extractor.py`
- [ ] Read `IV_POS_8_NOTES_FOR_PRO.md` NFP-7, NFP-8, NFP-9 for the Pro-facing framing of D1.B decisions (will be quoted in the Batch 3 `D1B_SUBSECTION.md`)
- [ ] Read `IV_POS_8_D1_REVISIT_PLAN.md` v0.4 §3.1 + §3.3 for D1↔D2 coordination context
- [ ] **Critical pre-read:** §0.1.1 (K vs CGC + bug-proximity), §0.4 (folklore-vs-facts), §1.2 (`parse_memory_byte_addr`), §1.5 (hybrid counting), §3.2 (ELF-mandatory Batch 1.5)
- [ ] Note `coverage_db.py:162-173` comment was corrected by Opus on 2026-06-17 to accurately describe the Python dict-repr format actually stored (memory: `{'addr', 'byte_addr', 'type', 'wrote', 'expected', 'mismatch_cycle'}`; cycle: `{'index', 'plus', 'minus'}`). Earlier comment claimed `%u` decimal; that was Phase-III planning intent, never the actual stored format. Composer should read the corrected comment, NOT the v0.1 spec text that still cites the old "decimal" wording (this checklist supersedes)
- [ ] Confirm `cgc_variants.py` does NOT live in `a4/standalone/` (production) — it lives in `a4/runs/iv_pos_7/analysis/`
- [ ] Confirm no edits to `compressed_global_extractor.py` (§2.2 out-of-scope)
- [ ] Implement Batch 1 tasks 1–5 in §3.1 exactly as scoped
- [ ] Run unit tests + smoke validation
- [ ] Write Batch 1 Composer report: `a4/docs/cloud2/composer/D1B_BATCH1_REPORT.md` with sections (data audit summary, smoke output, test pass count, file list, open questions for Opus review)
- [ ] Push branch `cloud2` with single squashed commit
- [ ] Notify chat for review checkpoint

---

## 9. Revision history

| Date | Author | Change |
|---|---|---|
| 2026-06-17 | Opus | Initial draft v0.1. 4 batches (Batch 1 foundation, Batch 1.5 page_class derivation, Batch 2 full analysis, Batch 3 recommendation + handoff). 6 Ivan-decision questions (Q-PC-1 through Q-PC-4, Q-CORPUS-1, Q-BATCH-MODEL). Page_class adopts the semantic-memory-use-class reading per Composer + Ivan investigation 2026-06-17; layout map is empirically derived from corpus + (if available) guest ELF, with Pro disclosure protocol. K-window guidance is a Batch-3 hand-off output, not a D1.B decision (per Ivan's K-timing pushback 2026-06-17). |
| 2026-06-17 | Opus | v0.2 — Composer pushback fixes (7 points, all verified against source): (1) **K hand-off removed** from D1.B Batch 3 — `ExponentialDecayFloor.K` is driven by `_local_discoveries` (cumulative legacy `coverage` row count) per `bandit_ts.py:98-100, 190-191` and `fuzzer.py:652-660`, NOT by CGC; renamed `d1e_handoff_K_window.md` → `d1e_handoff_CGC_saturation.md`; added §0.1.1 "Three saturation curves" table; called out optional `L_floor` architectural change as new D1.E-spec decision. (2) Conflation pre-empted via §0.1.1. (3) **Hybrid counting rule added** as new §1.5 — memory-family re-bucket + lookup-family pass-through (verified `compressed_global_extractor.py:298-320`: lookup families have no `address_region`); sanity invariants scoped to memory-subset OR explicit hybrid total in §1.5.1. (4) **Q-PC-2 default flipped** to ELF primary, empirical gap-fill only — Composer rightly noted address-frequency histograms reflect where mutations landed, not guest layout semantics. (5) Editorial: "Batch 2" stub label → "Batch 1.5"; unit tests moved to `a4/runs/iv_pos_7/analysis/test_cgc_variants.py` (matches existing convention); `_ADDRESS_REGION_MAP` corrected from "10-entry" to "9-entry + invalid fallback". (6) Inequality chain rescoped per §1.5.1. (7) §7 reorganized: only Q-CORPUS-1 blocks Batch 1; Q-PC-1..3 block Batch 1.5; Q-PC-4 blocks Batch 3 subsection; Q-BATCH-MODEL is process preference with Composer-suggested 1 ‖ 1.5-research overlap as default. Also fixed revisit plan §3.1.1 stale wording (log4 not equivalent to production log2; page_class is semantic not "region + access pattern"). |
| 2026-06-17 | Opus | v0.3 — Composer ELF-investigation incorporated (all 11 factual claims verified by Opus: ELF presence/sha/sections, memory.rs constants, dict-string `address` format, ctx_json richness, USER_PC_RANGE as PC band, PHASE_3 folklore, D8 origin, etc.). Substantive edits: (1) §0.1.1 **reframed per Ivan's Pro-intent restatement** — K decays on `_local_discoveries` per Pro §7 (verbatim formula cited); CGC + bug-proximity feed Bernoulli learning (L0+L1); `L_floor` option formally REMOVED as anti-Pro (would prevent floor decay, defeating staged-exploration design). (2) **New §0.4** acknowledging folklore provenance (PHASE_3 paper sketch, D8 unverified) vs verified sources (ELF + memory.rs + GLOSSARY) — including verified `_PAGE_CLASS_USER_LAYOUT` table for sha2-host. (3) §1.1 added rows for Guest ELF (canonical path, 248292 bytes, readelf-parseable, cursorignore note), memory.rs constants, HOST_ECALL provenance, `global_failures.address` actual dict-string format (`{'addr':..., 'byte_addr':..., 'type':..., ...}`), and ctx_json actual richer content (includes `cycle_phase`/`txn_role`); clarified USER_PC_RANGE as PC band, NOT memory layout. (4) §1.2 page_class draft layout populated with verified sha2-host ELF values + new `parse_memory_byte_addr(address: str)` helper using `ast.literal_eval` (fixes v0.1 assumption of int parsing). (5) §1.3 Path 3 description updated for dict-string format + ctx_json richness note. (6) §3.2 **Batch 1.5 fully rewritten** as deterministic, ELF-mandatory derivation — replaces "locate ELF if found" exploratory path with hardcoded canonical path + hard-fail (with `cargo build` instruction) if missing; readelf-based section parsing; empirical histograms = validation-only gate (`user_other` ≤ 15%); artifacts `d1b_guest_elf_layout.json` + `d1b_page_class_layout.md` shipped to `a4/runs/iv_pos_8/d1b/`; new Q-PC-EHF decision on fold/split `.eh_frame`. (7) §6 risk "ELF cannot be located" marked **eliminated** (Composer audit verified presence). (8) Q-PC-2 default tightened to **ELF MANDATORY** (was "ELF primary, empirical gap-fill"). (9) §3.3 Batch 3 hand-off clarified — D1.B feeds D2 reward CGC choice + D1.E L0, not K. |

| 2026-06-17 | Opus | v0.3.1 — Composer-flagged stale-string + first-hit-semantics patch over v0.3 (Composer review verdict: greenlight Batch 1; agree on all 5 stale lines + first-hit gap + 1 minor wording). Fixes: (1) §2.1 "K-window guidance" → "L0 + D2 reward CGC choice; NOT K"; (2) §3.1 task 1 "parsed as int" → `parse_memory_byte_addr` + explicit None-rate sanity check; (3) §3.3 Batch 2 goal "D1.E K-choice" → "D1.E L0 rewire"; (4) §3.4 exit criteria `d1e_handoff_K_window.md` → `d1e_handoff_CGC_saturation.md` with explicit naming history note; (5) §8 checklist v0.1 → v0.3.1; (6) **NEW §1.3 + §3.3 Batch 2 task 1: first-hit semantics** — page_class curves must derive `MIN(mutation_id)` per `(family, page_class(byte_addr))` from `global_failures` to be comparable with production `compressed_global_coverage.first_hit_mutation_id` (without this, page_class curves cannot be compared to production / region_only / log4_explicit curves; only final counts would be meaningful); (7) §4 risk wording tightened — Q-PC-2 is ELF-mandatory, so `user_other > 15%` triggers **layout extension** (sub-split `user_bigint`, check D42 journal buffer, additional ELF sections), NOT empirical fallback; (8) §0.4 NEW gap-folding instruction for inter-section padding (`.text`↔`.rodata` 1028 B gap, `.data`↔`.bss` 4 B gap, `STACK_TOP`↔`TEXT_START` 1 KB gap) — implementation uses half-open-up-to-next-section convention. **Source-code drift flagged in §8:** `coverage_db.py:162-163` comment claims `address` is "decimal matching C++ %u printf in ffi.cpp" — this is wrong; actual format is Python dict-repr per direct SQL inspection. Comment-only fix pending Ivan greenlight; does NOT affect D1.B Batch 1 work. |
| 2026-06-17 | Opus | v0.4 — Batch 1 ACCEPTED 15:30 EDT; mid-implementation discovery via Composer's root-cause analysis found `_coerce_broken_addr` field-priority bug (`compressed_global_extractor.py:216` prefers Hook-3 `addr` over `byte_addr` despite `byte_addr = addr × 4` invariant; verified by Opus independent SQL: V5 s1234 58.9%, V1 s1234 53.2%, decayexp s1234 55.7% region mismatch). NEW §3.2.5 Batch 1.6 inserted between Batch 1.5 and Batch 2 to land one-line field-priority fix + replay tooling + Batch 1 report amendment. Batch 2 prerequisite added: production baseline = corrected replay, not stored. Lookup/local/arms unaffected (verified). NFP-10 added to NOTES_FOR_PRO. Revisit plan updated to v0.5. Re-dispatch of R2 V1-V5 explicitly NOT scheduled — `hook3_raw` preserves raw payloads for post-hoc replay. |
| 2026-06-17 | Opus | v0.4.3 — Composer Batch 1.5 review pushback (5 substantive points, all accepted): (P1) **Reframing**: Batch 1.5b is an ENHANCEMENT, not a bug fix. §0.4 already designed `user_other` as the upper-band catch-all and the 15% gate was sized to allow it. Composer's Batch 1.5 correctly implemented v0.4.1; 1.5b promotes the implicit catch-all to explicit `user_dynamic` for Pro-disclosure clarity. (P2) **Count correction**: Opus's earlier ad-hoc audit count of 3327 was understated due to non-canonical glob; Composer's canonical `cat_a_db_list()` measurement is **4850 hits / 4326 distinct byte_addrs**. The 100%-in-upper-band conclusion holds; only the magnitude was wrong. (P3) **Opus hex errors in v0.4.2 §1.2 corrected**: hand-typed values `0x0021A2F8` (text hi), `0x0022153C` (data lo), `0x00221688` (_end) were transcription errors — actual ELF/JSON values are `0x00219DB8`, `0x0022133C`, `0x00221488` respectively. `0x0021A2F8` in particular sits 1344 bytes INSIDE `.rodata` (not at any section boundary). Fix: v0.4.3 §1.2 removes hand-typed hex entirely and defers to `d1b_guest_elf_layout.json` for ALL numeric values; only the schema/label set is shown inline. (P4) **Batch 2 impact correction**: at the CGC-key level, `cgc_key_page_class = f"{family}|{page_class(addr)}"` is a pure label string — `user_other → user_dynamic` is a 1:1 label swap, NOT a new discriminator. Page_class first-hit COUNT is unchanged; only key STRINGS change. v0.4.2 framing that "Batch 2 metrics would carry residual unclassified" was overstated — 1.5b is for Pro-facing label hygiene, not metric validity. (P5) **Invariant correction**: `page_class_memory ≈ 14-16` (v0.4.2 speculation) reverted to `≈ 13-15` (v0.4.1 original). The +1 from `user_dynamic` was wrong because `user_other` already contributed one key under the old layout — relabeling doesn't add a key. (P-naming) **Upper bound**: `user_dynamic` extends to `0xBFFF0000` (D8 `user` band boundary per `_ADDRESS_REGION_MAP`), NOT `0xC0000000` (GUEST_MAX_MEM); avoids overlapping with `user_bigint` which Q-PC-3 passes through unchanged. v0.4.2 history below; v0.4.2 itself contained the Opus errors documented in P3 and is FORMALLY SUPERSEDED. |
| 2026-06-17 | Opus | v0.4.2 — [SUPERSEDED by v0.4.3] Composer Batch 1.5 implementation completed (15/15 tests pass, gate passes at 3.158%); Opus audit found 100% of `user_other` residual concentrates in `[HOST_ECALL_HI=0x42000100, GUEST_MAX_MEM=0xC0000000)`. New **Batch 1.5b §3.2.4** inserted as 30-minute layout-completeness patch. **v0.4.2 contained Opus hex-conversion errors (text hi, data.addr, _end hand-typed values) caught by Composer review — see v0.4.3 P3 for corrections.** Spec §1.1 memory.rs row updated. §3.3 page_class_memory expectation updated from `≈ 13-15` to `≈ 14-16` post-Batch-1.5b (later reverted in v0.4.3 per P5). |
| 2026-06-17 | Opus | v0.4.1 — Composer Batch 1.6 implementation completed + review feedback (4 points, all verified): (P1) §3.3 Batch 2 task 1 corrected — internally inconsistent in v0.4 (prereq said production from replay but task 1 said "read `compressed_global_coverage.first_hit_mutation_id` directly"; now all 4 variants derive memory keys from corrected replay first-hit map). (P2) §3.3 prerequisite + task 1 + sanity invariants reframed — Batch 1's "memory channel dead" finding was **double-masked** (bug + coarsening); if Batch 2 fixes only production baseline but leaves region_only/log4_explicit on stored ctx_json, comparison is meaningless. ALL 4 variants now derive memory from corrected replay; corrected expectations are `region_only ≈ 9 regions`, `log4_explicit ≈ 30-50 keys`, `page_class ≈ 13-15 keys`. (P3) §3.2.5 housekeeping — `D1B_BATCH1_REPORT.md` amendment is **§9** (after existing §8), not §7; NFP-10 wording is "Opus drafted, Composer verifies", not "Opus drafts; Composer reviews"; exit criteria reference Composer's actual test counts (85 pass in extractor file, 515 in standalone suite, 45 in iv_pos_7 analysis). (P4) §3.2.5 task 3 now documents the load-bearing memory-replay / lookup-snapshot methodology split: memory re-extracted from `hook3_raw.raw_json` via patched extractor (`major=0` safe since memory ctx doesn't depend on major), lookup taken from `hook3_raw.compressed_ctx_json` runtime snapshot (patch-invariant; preserves 0/30 sanity-check invariance). Replay measured impact: mean memory Δ +20.7/DB (range 0-32), V5 s1234: 89→117 (+31.5%), V1 s1234: 69→72 (+4.3%), lookup unchanged (0/30 mismatches). v0.4 history retained above for traceability. |

*End of `IV_POS_8_D1_B_SPEC.md` v0.4.3.*
