# IV.POS.8 — Phase 3 Spec: D2.D — Variant dispatch + inactive L1 logging

**Version:** v1.0 — **LOCKED FOR IMPLEMENTATION** (authored by Opus-CP acting as D2-Opus, 2026-06-20)
**Phase:** New_Master §2 **Phase 3** (variant dispatch + 4-variant checkpoint) · Pro: `ProG_Report_4.md` §Phase 3, **Q3 (L1 inactive logging)**, §Phase-4 territory metrics (consumer)
**Governing plan:** [`New_Master.md`](New_Master.md) §2 Phase 3, §1 LOCKED-decisions (variant set)
**Predecessors (closed):** D2.C (`IV_POS_8_D2_C_SPEC.md` v0.5 — Arguzz bridge, CGC fix), **Phase 2 Bernoulli** (`IV_POS_8_D2_BERNOULLI_FLOOR_SPEC.md` v1.0 — complete, verified)
**Sibling/coordination:** **D1.E** (`IV_POS_8_D1_E_SPEC.md` v0.2.1 — spec-only, not built). **D2.D builds the L1 *logging* substrate D1.E specified; D1.E later adds *activation*.** See §3.4 + Risk D1.
**Baseline:** working tree at Phase-2-complete — full sweep **757 passed / 27 skipped** (verified 2026-06-20). New tests add to this.

---

## 0. Scope & non-goals

### 0.1 What D2.D IS
The wiring + validation layer that makes the **four checkpoint variants** runnable through one consistent surface, plus the **inactive logging of the three D1.C L1 bug-proximity signals** so Phase 4 (D2.G) can re-audit them on V6/Hybrid telemetry before anyone activates them. Concretely:

1. **Variant CLI/dispatch enablement** — expose `v6_cTS` and `hybrid_cTS` through `a4/standalone/cli.py fuzz --selector` (today they work *inside* `A4Fuzzer` but are **not** accepted by the CLI), and establish a **canonical variant registry** so the 4 variants (`V5_control`, `V6_uniform`, `V6_cTS`, `Hybrid_cTS`) have one source of truth for their launch config (selector/driver, Bernoulli, applied-accounting, kind sets, floor schedule). This unblocks Phase-3 POS dispatch (D2.F) and Phase-4 labeling (D2.G).
2. **Per-variant validation** — smoke gates that each variant pulls the kinds/arms it should, and that **`applied_accounting_mode` works at the variant level** (F9 — its first real use; D2.C *wired* it, D2.D *validates* it).
3. **Inactive L1 logging (Pro Q3)** — compute the three D1.C signals (`mutation_substrategy_uniqueness`, `d_loc_le_2_flag`, `singleton_failure_flag`) **online** in fresh fuzzer runs and **persist** them (plus the counterfactual enriched bit `bandit_success_l1`), **without** feeding them into the bandit's reward. The bandit keeps learning from the base `compute_bandit_success(l,g,s)`.

### 0.2 What D2.D is NOT (non-goals)
- **NOT activating L1.** The bandit's learning signal is unchanged. `bandit_success_l1` is a logged counterfactual only. Activation is **D1.E** (Phase 5, gated).
- **NOT the POS campaign.** Authoring/running the 8-job smoke + production tail is **D2.F**. D2.D provides the dispatch *path* + a local/mocked smoke + manifest stubs; D2.F runs them on POS.
- **NOT the analysis.** Territory/proximity/propagation analysis is **D2.G**. D2.D only ensures the data (L1 signals, applied-pull accounting, variant labels) is *captured*.
- **NOT changing V5 behavior.** `V5_control` = archive reuse; the fresh-equivalent selector `cTS_semantic_v2` stays byte-identical (no Bernoulli, no L1 in its reward). V5 golden traces are an acceptance gate.
- **NOT changing the Bernoulli/applied-accounting mechanisms** (landed in Phase 2 / D2.C) — only validating them per-variant.
- **NOT touching** `bandit_ts.py`, `semantic_arm_universe.py`, `arguzz_invoke.py`, `arguzz_bridge.py`, `v6_driver_v2.py`, `semantic_zones.py`, `workspace/risc0-modified/`. (`v6_uniform_driver.py` is touched only if §2.3 routes it through the registry — see that section.)

### 0.3 Sequencing
D2.D is the first Phase-3 spec. It depends on Phase 1 (D2.C) + Phase 2 (Bernoulli), both complete. It **blocks** D2.E (integration tests), D2.F (POS dispatch), and therefore the 4-variant checkpoint.

---

## 1. Background — verified current state

### 1.1 The four variants and how each launches today
| Variant | Launcher (today) | Status | Config (`_arguzz_strategy_config`, `fuzzer.py:718-730`) |
|---|---|---|---|
| **V5_control** | `cli.py fuzz --selector cTS_semantic_v2` **OR archive reuse** | selector in CLI ✓; **checkpoint uses the R2 archive** | A4-only; no Bernoulli; applied_accounting **off** |
| **V6_uniform** | `python -m a4.standalone.v6_uniform_driver` (own CLI) | works ✓ (round-robin `ArguzzScheduler`, **no bandit**) | 11 Arguzz kinds, round-robin; no cTS |
| **V6_cTS** | `cli.py fuzz --selector v6_cTS` | **CLI rejects it** — `v6_cTS` not in `--selector choices` (`cli.py:205-218`) | `(ALL 11 Arguzz kinds, [], applied=True)`; Bernoulli **on** (Phase 2) |
| **Hybrid_cTS** | `cli.py fuzz --selector hybrid_cTS` | **CLI rejects it** | `(4 SELECTED Arguzz kinds, A4 kinds, applied=True)`; Bernoulli **on** |

`v6_cTS`/`hybrid_cTS` are already in `V2_BANDIT_STRATEGIES` + `ARGUZZ_CTS_STRATEGIES` (`fuzzer.py:132-151`) and fully handled inside `A4Fuzzer`; the **only** gap is the CLI `choices` allow-list (`cli.py:205-218`).

### 1.2 POS dispatch is already variant-aware
`a4/pos/run_campaign_pos.sh` branches: `A4_STRATEGY == "v6_uniform"` → the driver; **else** → `cli.py fuzz --selector "$A4_STRATEGY"`. Both branches already `export A4_COVERAGE_TOUCH=1 / A4_FAMILY_RESIDUE=1 / CONSTRAINT_CONTINUE=1` (and the cli branch adds `A4_GLOBAL_RESIDUE=1`). Manifests (`a4/pos/manifests/iv_pos_8/*.json`) carry `jobs[].strategy/seed/n/[b_count]/[telemetry_level]`. **So once `cli.py` accepts `v6_cTS`/`hybrid_cTS`, the POS path works** — the `else` branch passes the selector straight through.

### 1.3 The reward/telemetry path (where L1 hooks)
Both reward paths converge on `record_full_telemetry` (`telemetry_v2.py:157`), which already writes `reward_counterfactuals` (line 198) and `mutation_substrategy` (210):
- **Arguzz cTS path** (`_run_arguzz_cts_mutation`): `compute_reward → diag` (with `d_loc`) at `fuzzer.py:1198`; `compute_reward_v2_components` (1208); `compute_bandit_success(l,g,s)` (**1221**); `update_with_outcome(arm, outcome, success=bandit_success)` (**1225**); `_record_full_telemetry` (1240).
- **A4 path**: analogous at `fuzzer.py:1387-1495` (`compute_bandit_success` **1422**, `update` **1471/1473**, telemetry **1495**).
So the L1 signals are computable at both `compute_bandit_success` sites, and persisted through one telemetry entry point that **both** variants already call.

### 1.4 The three L1 signals (definitions LOCKED from D1.C; extractors specified in D1.E §1.2)
| Signal | Predicate | Online input (verified available) | Note |
|---|---|---|---|
| `d_loc_le_2_flag` | `1 if diag["d_loc"] <= 2 else 0` | `diag["d_loc"]` (in-memory, `fuzzer.py:1198/1387`) | Highest post-local fire (**60.7%** on V5) → opposite-saturation risk; **logged only** here. Production semantic incl. crash-mode `d_loc=0` schism (~1.1%). |
| `singleton_failure_flag` | `1 if len(failures) == 1 else 0` | `failures` list (in-memory) | Row form (D1.C shipped). 16.5% post-local. |
| `mutation_substrategy_uniqueness` | first occurrence of `(kind, composite_substrategy_key(kind, sub))` per campaign | `extract_mutation_substrategy(...)` (already in `telemetry_v2.py:77`) + per-campaign seen-set | **Exclude `INSTR_TYPE_MOD`** (degenerate all-NULL substrategy). 33.7% post-local. |

---

## 2. Design — variant dispatch

### 2.1 CLI enablement (LOCKED)
Add `"v6_cTS"` and `"hybrid_cTS"` to the `fuzz --selector` `choices` list (`cli.py:205-218`) and to the help text (mark them "IV.POS.8 D2.C/D2.D: Arguzz cTS / Hybrid cTS"). No other `cmd_fuzz` change is required — `A4Fuzzer` already accepts and dispatches them.

### 2.2 Canonical variant registry (LOCKED) — new module `a4/standalone/variants.py`
One source of truth for the 4 checkpoint variants, so dispatch, smoke, manifests, and D2.G labeling cannot drift. Shape:
```python
# a4/standalone/variants.py
from dataclasses import dataclass

@dataclass(frozen=True)
class VariantSpec:
    name: str                 # canonical: "V5_control" | "V6_uniform" | "V6_cTS" | "Hybrid_cTS"
    launcher: str             # "cli" | "driver"
    selector: str | None      # cli --selector value, or None for driver
    driver_module: str | None # e.g. "a4.standalone.v6_uniform_driver", or None
    bernoulli_floor: bool
    applied_accounting: bool
    surface: str              # "a4" | "arguzz" | "hybrid"
    archive_reuse: bool       # True for V5_control in the checkpoint
    notes: str

CANONICAL_VARIANTS: dict[str, VariantSpec] = {
    "V5_control":  VariantSpec("V5_control",  "cli", "cTS_semantic_v2", None, False, False, "a4",     True,  "checkpoint reuses R2 archive; cTS_semantic_v2 = fresh-equivalent"),
    "V6_uniform":  VariantSpec("V6_uniform",  "driver", None, "a4.standalone.v6_uniform_driver", False, False, "arguzz", False, "round-robin ArguzzScheduler, no bandit"),
    "V6_cTS":      VariantSpec("V6_cTS",      "cli", "v6_cTS", None, True,  True,  "arguzz", False, "all 11 Arguzz kinds, cTS, Bernoulli"),
    "Hybrid_cTS":  VariantSpec("Hybrid_cTS",  "cli", "hybrid_cTS", None, True, True, "hybrid", False, "4 selected Arguzz + A4 kinds, cTS, Bernoulli"),
}

def resolve_variant(name: str) -> VariantSpec: ...
def variant_launch_command(name, *, host, db, seed, num, host_args) -> list[str]: ...  # for smoke/POS reference
```
The registry's `bernoulli_floor`/`applied_accounting`/`surface` fields are **asserted against the live fuzzer behavior** in tests (§7 Layer-1) so the registry can never silently diverge from `_arguzz_strategy_config` + the Phase-2 gate. The registry is **descriptive/validating**, not a new execution path — `cmd_fuzz` and `run_campaign_pos.sh` keep their existing logic; the registry is the canonical reference they (and tests/manifests/D2.G) agree with.

### 2.3 POS dispatch (LOCKED — minimal)
`run_campaign_pos.sh` already handles all 4 (v6_uniform branch + cli else-branch). D2.D's only POS-side deliverables: (a) confirm the else-branch accepts `v6_cTS`/`hybrid_cTS` after §2.1; (b) ship **manifest stubs** under `a4/pos/manifests/iv_pos_8/` for the 4-variant smoke (model on `d2c_v6_uniform_smoke.json`), one job per fresh variant. **Do NOT refactor `run_campaign_pos.sh`'s branching** (the v6_uniform special-case is fine; a registry-driven rewrite is out of scope). Running these manifests on POS is **D2.F**.

> **Env note:** the fuzzer-based variants get `A4_COVERAGE_TOUCH` from **two** places now — the POS shell (`run_campaign_pos.sh`) *and* the bridge default (`arguzz_bridge.DEFAULT_ARGUZZ_SUBPROCESS_ENV`, from the F13 fix). These are consistent (both set it to `"1"`); the bridge is the authoritative one for correctness, the shell export is belt-and-suspenders. No action — just don't remove either.

---

## 3. Design — inactive L1 logging (Pro Q3)

### 3.1 Principle
Compute the 3 signals online, **persist them**, and **do not let them touch the bandit's reward**. The bit the bandit learns from stays `compute_bandit_success(l_new, g_new, s_new)` (base). We additionally persist:
- the **3 individual signal flags** (so D2.G can re-audit each channel's fire rate / orthogonality on V6/Hybrid), and
- the **counterfactual enriched bit** `bandit_success_l1 = base_bit OR (any logged signal fired)` (so D2.G can compare "what the bandit would have learned" vs base).

### 3.2 Shared extractor module (LOCKED) — new `a4/standalone/l1_signals.py`
Houses the 3 extractors + `composite_substrategy_key(kind, sub_dict)` + `KIND_TO_SUBSTRATEGY_FIELDS` (ported from `a4/runs/iv_pos_7/analysis/bug_proximity.py:57-66/201-238`, **no cross-tree import**). This is the substrate **D1.E reuses** (§3.4). Pure functions + a tiny per-campaign state holder for the substrategy seen-set. Definitions verbatim from §1.4 / D1.E §1.2:
- `d_loc_le_2(d_loc) -> int`
- `singleton_failure(failures) -> int`  (`1 if len(failures)==1`)
- `substrategy_uniqueness(kind, sub_dict, seen: set, *, excluded_kinds=frozenset({"INSTR_TYPE_MOD"})) -> int`

### 3.3 Wiring (LOCKED — observe-only)
At **both** reward sites (`fuzzer.py:1221` Arguzz, `1422` A4), after `bandit_success = compute_bandit_success(...)`:
1. Compute the 3 signals from in-memory `diag["d_loc"]`, `failures`/`inv_result.failures`, and `extract_mutation_substrategy(...)` + `self._l1_substrategy_seen`.
2. Compute `bandit_success_l1 = 1 if (bandit_success or any(signal)) else 0`.
3. **Leave `update_with_outcome(..., success=bandit_success)` UNCHANGED** (base bit). ← the inactivity guarantee.
4. Thread the 3 flags + `bandit_success_l1` into `self._record_full_telemetry(...)` → `record_full_telemetry(...)` → `db.record_reward_counterfactuals(...)`.

Gating: a campaign param `l1_logging: bool = True` (on for all fresh fuzzer runs). When the universe/strategy is V5 archive-reuse it never runs (no fresh campaign). There is **no `l1_active` path in D2.D** — that is D1.E.

### 3.4 Schema + persistence (LOCKED)
Extend `reward_counterfactuals` (`coverage_db.py:340-348`) with **four** nullable columns, via `ALTER TABLE ... ADD COLUMN` (default NULL on existing archives — back-compat):
- `bandit_success_l1 INTEGER` (the counterfactual enriched bit) — **this is exactly D1.E's planned column**;
- `l1_substrategy_uniqueness INTEGER`, `l1_d_loc_le_2 INTEGER`, `l1_singleton_failure INTEGER` (the 3 individual flags, for per-channel re-audit).

Extend `record_reward_counterfactuals` (`coverage_db.py:524`) + `record_full_telemetry` (`telemetry_v2.py:157`) signatures with these four (all `Optional[int] = None`, default-NULL preserves back-compat for every other caller). `discovery_binary_reward` stays the **base** bit (unchanged) — preserves D1.C/D1.A comparability.

### 3.4.1 Cross-spec coordination with D1.E (FLAG — Risk D1)
D1.E (`IV_POS_8_D1_E_SPEC.md` v0.2.1) **designed this exact substrate but was never built**. D2.D now builds the **logging half**:
- D2.D ships: `l1_signals.py` extractors, the `bandit_success_l1` + 3-flag columns, the telemetry plumbing — all **observe-only**.
- D1.E (if it runs, Phase 5) then **only** adds: (a) feeding the enriched bit into the bandit's learning (the `compute_bandit_success(..., l1_signals=...)` extension + `update` call), (b) the opposite-saturation guard (post-local mean ≤ 0.75 on `[3000,6000)`), (c) the K/epoch decay config. It **reuses** `l1_signals.py` + the columns.
**Action:** D1.E's spec must be updated to "reuse D2.D's L1 logging substrate; build only activation + guard + decay." I have flagged this in central-planning (F14) for the D1 pair. **D2.D must not implement the activation path or the saturation guard** (those belong to D1.E and depend on its re-audit).

---

## 4. Locked decisions (Q&A)

| # | Question | Decision |
|---|---|---|
| **DD-Q1** | Unified `--variant` arg, or just add selectors? | **Add `v6_cTS`/`hybrid_cTS` to `--selector`** (minimal, matches POS) + a **descriptive registry** (`variants.py`) as the canonical reference. No new `--variant` execution flag (avoids a parallel dispatch path). |
| **DD-Q2** | L1: log only, or build D1.E's full machinery? | **Log only (observe-only).** Build the extractors + columns + plumbing (the substrate D1.E needs), but the bandit reward path is untouched. Activation = D1.E. |
| **DD-Q3** | Persist just `bandit_success_l1`, or the 3 individual flags too? | **Both** — `bandit_success_l1` (counterfactual) **and** the 3 flags (so D2.G re-audits per-channel fire rate/orthogonality, which a single OR'd bit can't show). |
| **DD-Q4** | Log L1 in `V6_uniform` (driver) too? | **No.** V6_uniform has no bandit and goes through the driver, not the fuzzer reward path. Its proximity signals (d_loc_le_2, singleton) are **derivable offline by D2.G** from its `failures`/`mutation_rewards`; substrategy_uniqueness is bandit-specific. Logging is scoped to the **fuzzer bandit variants** (`v6_cTS`, `hybrid_cTS`, and `cTS_semantic_v2` if run fresh). Documented for D2.G. |
| **DD-Q5** | Apply the opposite-saturation guard (≤0.75) in D2.D? | **No** — that guard governs *activation*; D2.D only logs. D2.G/D1.E evaluate it on the logged data. |
| **DD-Q6** | `INSTR_TYPE_MOD` in substrategy_uniqueness? | **Exclude** (degenerate all-NULL substrategy → spurious single fire). Matches D1.E Q-E-INSTR_TYPE_MOD. |
| **DD-Q7** | `d_loc` source / singleton form? | `diag["d_loc"]` (production semantic incl. crash schism); singleton = **row form** `len(failures)==1`. Matches D1.E Q-E-D_LOC-SOURCE / Q-E-SINGLETON-DEFINITION. |
| **DD-Q8** | V5_control fresh or archive? | **Archive reuse** for the checkpoint (per New_Master). `cTS_semantic_v2` remains the fresh-equivalent + stays byte-identical (no Bernoulli, no L1 in its *active* reward — it does log L1 as a counterfactual if run fresh, which does not affect its decisions). |
| **DD-Q9** | Batch count? | **3 batches** (dispatch / validation / L1 logging) — one more than New_Master's 2, justified by L1's intricacy + its V5-safety surface. |

---

## 5. File-by-file changes

| File | Change | Batch | Est. LOC |
|---|---|---|---|
| `a4/standalone/cli.py` | Add `v6_cTS`, `hybrid_cTS` to `fuzz --selector` choices + help text. | B1 | ~4 |
| `a4/standalone/variants.py` | **NEW** — `VariantSpec` + `CANONICAL_VARIANTS` + `resolve_variant`/`variant_launch_command`. | B1 | ~70 |
| `a4/pos/manifests/iv_pos_8/d2d_checkpoint_smoke.json` (+ stubs) | **NEW** — one job per fresh variant for the D2.F smoke. | B1 | doc |
| `a4/standalone/l1_signals.py` | **NEW** — 3 extractors + `composite_substrategy_key` + `KIND_TO_SUBSTRATEGY_FIELDS` (ported, no cross-tree import). | B3 | ~80 |
| `a4/standalone/fuzzer.py` | Per-campaign `self._l1_substrategy_seen`; compute 3 signals + `bandit_success_l1` at the two reward sites (1221/1422), **observe-only**; thread through `_record_full_telemetry`. `l1_logging` campaign param. | B3 | ~40 |
| `a4/standalone/telemetry_v2.py` | `record_full_telemetry` accepts + forwards the 4 new values to `record_reward_counterfactuals`. | B3 | ~10 |
| `a4/standalone/coverage_db.py` | `reward_counterfactuals` + 4 nullable columns (`ALTER TABLE` migration); `record_reward_counterfactuals` signature. | B3 | ~20 |
| Tests (new) | `test_d2d_variant_dispatch.py` (B1), `test_d2d_variant_smoke.py` (B2), `test_d2d_l1_logging.py` (B3). | — | ~250 |
| Docs | `New_Master.md` Phase-3 D2.D row; this spec §13 changelog. | — | doc |

---

## 6. What must NOT change (safety contract)

1. **V5 byte-identity:** `test_d2c_golden_trace_v5_decision_seq.py` + `test_d2c_golden_trace_v5_db_byte_identity.py` stay green. L1 logging must not perturb V5 *decisions* — it only **adds** counterfactual columns; it must not change `success=` into `update`/`update_with_outcome`, the RNG stream, or any existing column. (If `reward_counterfactuals` is in the Tier-2 byte-identity snapshot, the new columns are **NULL** for the V5 fixture run unless `l1_logging` is on for it — confirm in pre-flight and, if needed, regenerate the V5 fixture **only** after proving decisions are unchanged, or keep `l1_logging` off for the golden-trace harness.)
2. **Bandit learning path unchanged:** the `success=` argument to `update`/`update_with_outcome` at `fuzzer.py:1225/1471/1473` stays the **base** `compute_bandit_success(l,g,s)`. (The inactivity guarantee — assert it in tests.)
3. **`discovery_binary_reward` unchanged** (base bit; D1.C comparability).
4. **Frozen files** (§0.2) untouched.
5. **Full sweep** stays green (757 + new).

---

## 7. Test plan

### Layer 1 — pure-Python / construction (no binary)
- **Variant registry parity:** for each of the 4 `CANONICAL_VARIANTS`, assert its `bernoulli_floor`/`applied_accounting`/`surface` match what the live `A4Fuzzer` produces for that selector (construct the fuzzer, read `v2_scheduler.bernoulli_floor` + `applied_accounting_mode` + `_arguzz_strategy_config()`), so the registry cannot drift.
- **CLI accepts the new selectors:** `cli.py` argparse accepts `--selector v6_cTS` and `hybrid_cTS` (and still rejects garbage).
- **L1 extractor unit tests** (`l1_signals.py`): each predicate on crafted inputs; `INSTR_TYPE_MOD` exclusion; substrategy seen-set first-occurrence semantics; **cross-check** the extractor output against `bug_proximity.py`'s offline extractor on a small fixture (the values must match — this is what lets D2.G trust the logged columns).

### Layer 2 — fuzzer integration (mocked invocation, real bandit; ≤10 real / stubbed)
- **Inactivity proof (the key test):** run a short `v6_cTS` (and `hybrid_cTS`) campaign with a mocked invocation; assert (a) `reward_counterfactuals.bandit_success_l1` + the 3 flag columns are populated non-NULL; (b) the bandit's `update_with_outcome` was called with the **base** bit (monkeypatch/spy on the scheduler, or assert the decision/arm sequence is byte-identical to a run with L1 logging forced off). **L1 must not change a single bandit decision.**
- **Per-variant arm coverage:** `v6_cTS` pulls only Arguzz kinds; `hybrid_cTS` pulls both A4 + Arguzz surfaces (≥1 each); kinds match `_arguzz_strategy_config`.
- **applied-accounting variant smoke (F9):** with a mixed APPLIED/SKIPPED mock stream, assert `v6_cTS`/`hybrid_cTS` advance bandit pulls only on APPLIED (cold-start completes in applied-pull terms), confirming `applied_accounting_mode=True` behaves at the variant level. (First real exercise of F9.)

### Layer 3 — V5 unchanged (existing gates)
The two V5 golden traces + `test_reward_v2.py` (`compute_counterfactuals` byte-identical) + the Phase-2 Bernoulli tests stay green. Acceptance gate.

### Layer 4 — schema/migration
- `reward_counterfactuals` gains 4 columns; opening a pre-D2.D archive DB reads cleanly with them NULL; `record_reward_counterfactuals(...)` with the new kwargs omitted still works (back-compat).

### Layer 5 — real-binary smoke (≤10 mutations local; >10 → POS per the §15 policy)
A ≤10-mutation local `v6_cTS` run end-to-end through `cli.py fuzz --selector v6_cTS` (so the CLI path itself is exercised), asserting rows persist with `outcome` non-NULL, CGC non-empty (the F13 fix still holds via the bridge env), and the 4 L1 columns populated. The N≥50 per-variant scale smoke is **D2.F (POS)**.

---

## 8. Batch structure + Composer directives

**Read first:** this spec; `cli.py` (whole); `fuzzer.py:1198-1260` (Arguzz reward site) + `1387-1500` (A4 reward site) + `633-660` (`_record_full_telemetry`); `telemetry_v2.py:77-115` (`extract_mutation_substrategy`) + `157-210` (`record_full_telemetry`); `coverage_db.py:340-348/524-544` (reward_counterfactuals); `a4/runs/iv_pos_7/analysis/bug_proximity.py:57-66/192-249` (signal definitions to port); `IV_POS_8_D1_E_SPEC.md` §1.2 (the extractor blueprint you're implementing the logging half of) + §3.4.1 here (do NOT build activation).

**Pre-flight (record results):**
```bash
python -m pytest a4/standalone/tests -q                                   # expect 757 passed / 27 skipped
python -m pytest a4/standalone/tests/test_d2c_golden_trace_v5_decision_seq.py \
                 a4/standalone/tests/test_d2c_golden_trace_v5_db_byte_identity.py -q   # V5 gate
grep -n "campaign_params\|reward_counterfactuals" a4/standalone/tests/test_d2c_golden_trace_v5_db_byte_identity.py  # is reward_counterfactuals in the Tier-2 snapshot? (decides §6.1 handling)
grep -n "record_reward_counterfactuals\|record_full_telemetry" a4/standalone/fuzzer.py a4/standalone/telemetry_v2.py  # confirm both reward paths persist it
```

- **Batch 1 — Variant dispatch.** `cli.py` selector additions (§2.1); `variants.py` registry (§2.2); manifest stubs (§2.3); `test_d2d_variant_dispatch.py` (Layer-1 registry parity + CLI accept). **Gate:** full sweep green; V5 gates green.
- **Batch 2 — Per-variant validation.** `test_d2d_variant_smoke.py` (Layer-2 arm-coverage + applied-accounting F9 smoke, mocked). No production-code change beyond what B1 added. **Gate:** the F9 applied-accounting smoke passes for both `v6_cTS`/`hybrid_cTS`.
- **Batch 3 — Inactive L1 logging.** `l1_signals.py` (§3.2); fuzzer wiring at both reward sites (§3.3, observe-only); `telemetry_v2`/`coverage_db` schema + plumbing (§3.4); `test_d2d_l1_logging.py` (Layer-1 extractors + Layer-2 inactivity proof + Layer-4 migration). **Gate:** the inactivity proof (L1 changes zero bandit decisions); V5 golden traces byte-identical; `discovery_binary_reward` unchanged.

**Stop-and-report triggers:** (a) any V5 golden trace changes → stop (L1 logging leaked into the decision path); (b) you find the bandit's `success=` arg would change → stop (that's activation = out of scope, D1.E); (c) `reward_counterfactuals` turns out **not** to be persisted on the Arguzz path → stop and report (the L1 persistence target moves); (d) editing any frozen file → stop.

---

## 9. Acceptance checklist
- [x] `cli.py fuzz --selector` accepts `v6_cTS` + `hybrid_cTS`; help updated.
- [x] `variants.py` registry present; Layer-1 parity test asserts registry matches live fuzzer config for all 4 variants.
- [x] Manifest stubs for the 4-variant smoke present under `a4/pos/manifests/iv_pos_8/`.
- [x] Per-variant arm-coverage smoke green; **applied-accounting (F9) variant smoke green** for `v6_cTS`/`hybrid_cTS`.
- [x] `l1_signals.py` extractors match reference definitions; `INSTR_TYPE_MOD` excluded.
- [x] `reward_counterfactuals` has `bandit_success_l1` + 3 flag columns; migration reads old DBs as NULL.
- [x] **Inactivity proof green** — L1 logging changes zero bandit decisions; `success=` to `update*` is the base bit; `discovery_binary_reward` unchanged.
- [x] **V5 byte-identity (Tier-1 + Tier-2) green.**
- [x] Layer-5 ≤10-mutation real-binary `cli.py fuzz --selector v6_cTS` smoke (gated `A4_REAL_BINARY=1`).
- [x] Full sweep green (780 passed / 27 skipped); no frozen file touched.
- [x] New_Master Phase-3 D2.D row → DONE; §13 changelog updated. **D1.E coordination flagged (F14).**

---

## 10. Risks / flags

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| **DD-PI-1** | L1 logging leaks into the bandit decision path → changes V6/Hybrid behavior or V5 byte-identity. | **High** | Observe-only wiring (§3.3); the inactivity proof (Layer-2) + V5 golden traces are hard gates; `success=` arg explicitly unchanged. |
| **D1 — cross-spec coordination** | D2.D builds the L1 substrate D1.E assumed it would build → D1.E spec must change or risk duplication/merge conflict. | **High** | §3.4.1 splits cleanly (D2.D=logging, D1.E=activation+guard+decay) using a shared `l1_signals.py`. **Flagged as F14**; D1 pair must update D1.E to reuse the substrate. |
| **DD-PI-2** | `reward_counterfactuals` is inside the Tier-2 byte-identity snapshot → new columns/NULLs break the V5 fixture. | Med | Pre-flight grep (§8); keep `l1_logging` off for the golden-trace harness or regenerate the V5 fixture only after proving decisions unchanged. |
| **DD-PI-3** | Registry drifts from real fuzzer behavior. | Med | Layer-1 parity test asserts registry == live config for all 4 variants. |
| **DD-PI-4** | V6_uniform has no L1 logging → D2.G expects it everywhere. | Low | DD-Q4 documents: V6_uniform signals are D2.G-offline-derived; only bandit variants log online. Carry this into the D2.G spec. |
| **DD-PI-5** | F9 (`applied_accounting`) first real use surfaces a bug. | Low–Med | Dedicated F9 variant smoke (Layer-2) is the gate — this is the intended first exercise. |
| **DD-PI-6** | `d_loc_le_2` at 60.7% fire could mislead D2.G if read as a "good" signal. | Low | It is **logged only**; the saturation judgment is D2.G/D1.E's (≤0.75 guard lives there, not here). Documented. |

---

## 11. Tracked implementation issues (LIVING ANNEX)

| ID | Issue | Batch | Status | Resolution |
|---|---|---|---|---|
| **ISS-DD-1** | `bug_proximity.py` not importable standalone for cross-check test (relative `.metrics` import). | B3 | **RESOLVED** | Layer-1 test uses inline reference predicates matching ported `l1_signals.py` definitions; production path uses `l1_signals.py` only. |

---

## 12. Sequencing & dependencies
- **Depends on:** D2.C (complete), Phase 2 Bernoulli (complete).
- **Blocks:** D2.E (integration tests), D2.F (POS dispatch + checkpoint), D2.G (analysis labeling/L1 re-audit).
- **Coordinates with:** **D1.E** — D2.D builds the L1 logging substrate; D1.E reuses + activates (F14).
- **Carry-forward:** ⚑ F12 (N=10000 for cTS variants in D2.F for cold-start fairness); ISS-1 (D2.G fault-corroboration residual).

---

## 13. Changelog
| Date | Author | Version | Notes |
|---|---|---|---|
| 2026-06-20 | Composer | v1.0 DONE | B1–B3 implemented. Report: `composer/D2D_B1_B3_COMPOSER_REPORT.md`. Sweep 780/27. |
| 2026-06-20 | Opus-CP (acting D2-Opus) | v1.0 LOCKED | Initial spec. Variant dispatch = `--selector` additions + descriptive `variants.py` registry (no parallel exec path); POS already variant-aware. Inactive L1 logging = build D1.E's logging substrate (`l1_signals.py` + `bandit_success_l1` + 3 flag columns) observe-only, bandit reward untouched; D1.E adds activation (F14 coordination). Grounded in `cli.py:205-218`, `fuzzer.py:718-730/1198-1260/1387-1500`, `telemetry_v2.py:157-210`, `coverage_db.py:340-348/524-544`, `bug_proximity.py:57-249`, `IV_POS_8_D1_E_SPEC.md` §1.2, `ProG_Report_4.md` Q3. |
