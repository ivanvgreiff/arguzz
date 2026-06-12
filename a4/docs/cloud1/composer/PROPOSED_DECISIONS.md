# Proposed D-Decisions — Composer

**Status**: Phase 6 proposals awaiting Opus review (Phases 4–5 accepted in `CLOUD1_DECISIONS_FOR_PRO_R2.md`)

---

## Phase 4 (accepted — D20–D27)

D-A..D-D filed 2026-06-08; see `CLOUD1_DECISIONS_FOR_PRO_R2.md` and `PHASE_4_COMPOSER_SUMMARY.md`.

## Phase 5 (accepted — D28–D33)

D-E..D-I filed 2026-06-08; see `CLOUD1_DECISIONS_FOR_PRO_R2.md` and `PHASE_5_COMPOSER_SUMMARY.md`.

---

## Phase 6 — Extended Logging

**Date**: 2026-06-08

### D-J — `value_class` taxonomy

**Pro spec** (`PHASE_6_LOGGING.md` §6.1): `zero | small | large | bit_pattern` for value-mutating kinds.

**Our choice (proposed D34)**:

| Class | Rule |
|---|---|
| `zero` | `mutated_value & 0xFFFFFFFF == 0` |
| `bit_pattern` | `(original ^ mutated).bit_count() <= 4` and XOR ≠ 0 |
| `small` | `mutated_value < 256` OR `abs(mutated - original) < 256` (32-bit) |
| `large` | everything else |

**Type**: U (Pro names classes, no algorithm)

**Reasoning**: Matches intuitive buckets for ablation analysis; `bit_pattern` catches single-bit flips from `BitFlipValueGenerator`.

**Risk if wrong**: One function change in `classify_value_class()`.

---

### D-K — Default `--telemetry-level` per selector

**Pro spec** (`PHASE_6_LOGGING.md` §6.3): `full` default for IV.POS.7 new variants; `standard` for legacy.

**Our choice (proposed D35)**:

- If CLI omits `--telemetry-level`: **`full`** when `selector_strategy ∈ V2_BANDIT_STRATEGIES`, else **`standard`**.
- Explicit `none` / `standard` / `full` always wins.

**Type**: P-range (phase doc states intent)

**Reasoning**: IV.POS.7 variants need full tables without requiring a new CLI flag every run; legacy `zoned`/`bandit` behavior unchanged unless user opts in to `full`.

---

### D-L — `hook3_raw.raw_json` shape

**Pro spec** (§12): "raw family details if small enough" — no schema.

**Our choice (proposed D36)**:

```json
{"family_residues": [...], "family_details": [...]}
```

Omit keys when empty; `compressed_ctx_json` is a JSON list of ctx dict strings (same as `GlobalMemoryCtx.to_json_str()` / parsed objects).

**Type**: U

**Reasoning**: Preserves both Hook 3 payloads without lossy merge; matches Phase 1 `record_hook3_raw` round-trip test style.

---

### D-M — `mutation_substrategy` for `MEM_VAL_MOD` without explicit `byte_lane`

**Pro spec**: byte_lane / bit_mask for MEM_VAL_MOD.

**Our choice (proposed D37)**:

- `byte_lane` = `(original_value ^ mutated_value).bit_length() - 1` clamped to 0..31 (index of highest differing bit), or 0 if equal.
- `bit_mask` = `original_value ^ mutated_value` (32-bit XOR mask).

**Type**: U

**Reasoning**: Fuzzer config does not currently carry byte_lane; XOR mask is the actionable decomposition for offline analysis.

---
