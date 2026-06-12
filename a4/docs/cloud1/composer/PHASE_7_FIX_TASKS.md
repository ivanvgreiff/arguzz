# Phase 7 — Composer fix tasks (post-Opus investigation)

**From**: Opus
**To**: Composer
**Date**: 2026-06-09
**Authoritative report**: `a4/docs/cloud1/phases/PHASE_7_INVESTIGATION_REPORT.md`

## TL;DR

The current 7c re-run you're doing will produce results that are not interpretable — the verifier's architecture is wrong (proven in the report §2). Please **stop it** and switch to the work below.

Two of the items are **Phase 8 blockers** (Task 1 + Task 2). One is a **G2 blocker** (Task 4). The remaining two are smaller follow-ups. Do them in the order listed.

---

## IMMEDIATELY: stop the 7c re-run

It is processing samples through a verifier that compares the post-`<config>` expected values against a trace dump that `mod.rs` emits **before** the mutation hook runs. Every "fail" is therefore a false negative; every "pass" is a tautology or a fall-through. Re-running cannot change that. See report §2.2 for the direct stdout proof.

When you stop it, just note the kill time in your next summary so we know the artifact is incomplete; don't keep the partial JSON.

---

## TASK 1 — Fix Bug B (skip path doesn't update bandit) — **Phase 8 blocker**

**File**: `a4/standalone/fuzzer.py`
**Function**: `_run_v2_bandit_mutation`
**Lines**: around 870–872 (the `if config is None:` block).

**Change**: before returning `None`, call the v2 scheduler's `update()` with `success=0`. This makes phantom-arm pulls increment, so the cold-start floor terminates after 3 attempts/arm.

Current:

```startLine:endLine:a4/standalone/fuzzer.py
870:        if config is None:
871:            stats.skipped_mutations += 1
872:            return None
```

New (semantics, not exact text — match the selector_strategy branches that exist):

```python
if config is None:
    stats.skipped_mutations += 1
    # Bug fix: update the bandit on skip so phantom arms age out of cold-start
    # (otherwise pulls[phantom_arm] stays 0 forever and round-robin loops).
    if self.selector_strategy == "cTS_semantic_v2":
        self.v2_scheduler.update(kind, zone, 0)
    elif self.selector_strategy in ("kindUCB_zoned_v1", "kindUCB_zoned_v2_noQ"):
        self.v2_scheduler.update(kind, 0.0)
    elif self.selector_strategy == "kindTS_zoned_v2":
        self.v2_scheduler.update(kind, 0)
    return None
```

Make sure the early-return path at line 845 (the `step is None` skip for kind-only bandits) also gets the same treatment.

**Test**: add 1–2 unit tests that simulate a `_create_mutation` failure on every step for one specific arm, run `_run_v2_bandit_mutation` 4 times, and assert:
- `stats.skipped_mutations == 4`
- The bandit's `pulls[(kind, zone)]` is `4` (not `0`)
- After 3 skips the arm is no longer in `[a for a in scheduler.arms if scheduler.pulls[a] < 3]`

A minimal pytest using `unittest.mock` to make `_create_mutation` return `(None, 0, 0)` is enough.

---

## TASK 2 — Fix Bug A (universe builder includes phantom arms) — **Phase 8 blocker**

**File**: `a4/standalone/semantic_arm_universe.py`
**Function**: `SemanticArmUniverse.build`
**Lines**: 68–74 (the arm-construction loop).

**Change**: after computing `zone_steps_in_kind`, sample up to N candidate steps and only keep the arm if at least one candidate has a real mutation target. Use the actual per-kind `get_targets_at_step` from `a4.standalone.mutations.*`, not `InspectionData.get_valid_steps_for_kind`.

**Important**: this also has to be deterministic given a seed (the universe is used by all replicates and must produce identical arms). Use a separate `random.Random(seed)` instance, or just sample the first N and last N steps (deterministic, no rng needed). I recommend the deterministic approach to avoid adding another seed-dependence.

Suggested shape:

```python
from a4.standalone.mutations import (
    comp_out_mod, load_val_mod, store_out_mod, pre_exec_reg_mod,
    instr_type_mod, mem_val_mod, instr_word_mod, instr_word_mod_sur,
)

_MUTATION_MODULES = {
    "COMP_OUT_MOD":        comp_out_mod,
    "LOAD_VAL_MOD":        load_val_mod,
    "STORE_OUT_MOD":       store_out_mod,
    "PRE_EXEC_REG_MOD":    pre_exec_reg_mod,
    "INSTR_TYPE_MOD":      instr_type_mod,
    "MEM_VAL_MOD":         mem_val_mod,
    "INSTR_WORD_MOD_FULL": instr_word_mod,
    "INSTR_WORD_MOD_SUR":  instr_word_mod_sur,
}

def _arm_has_real_target(kind, zone_steps, data, probe_n: int = 8) -> bool:
    """Sample up to probe_n steps deterministically; True if any has a real target."""
    if not zone_steps:
        return False
    mod = _MUTATION_MODULES.get(kind)
    if mod is None:
        return True  # unknown kind — keep, fall back to runtime skip handling
    # Probe head + tail + a few middles deterministically.
    n = len(zone_steps)
    probe_idxs = sorted(set(
        list(range(min(probe_n, n)))
        + list(range(max(0, n - probe_n), n))
        + [n // 4, n // 2, 3 * n // 4]
    ))
    for i in probe_idxs:
        if i >= n:
            continue
        step = zone_steps[i]
        # PRE_EXEC_REG_MOD's get_targets_at_step takes an extra `strategy` arg.
        try:
            if kind == "PRE_EXEC_REG_MOD":
                t = mod.get_targets_at_step(step, data, strategy="next_read")
            else:
                t = mod.get_targets_at_step(step, data)
        except Exception:
            t = None
        # mem_val_mod / pre_exec_reg_mod return lists; others return Optional[Target].
        if isinstance(t, list):
            if t:
                return True
        elif t is not None:
            return True
    return False
```

Then in `build`:

```python
for kind in mutation_kinds:
    valid_set = set(valid_by_kind[kind])
    for zone in SEMANTIC_ZONES:
        zone_steps_in_kind = sorted(valid_set & set(z2s.get(zone, [])))
        if not zone_steps_in_kind:
            continue
        if not _arm_has_real_target(kind, zone_steps_in_kind, data):
            continue  # phantom arm — drop it
        arms[(kind, zone)] = zone_steps_in_kind
```

**Acceptance**: on the same `--in1 5 --in4 10` trace, the universe should report **47 arms** (not 53), and the 6 phantom arms from the report's §1.4.2 table should be dropped. Add an assertion test that they are absent.

**Don't forget**: `pre_exec_reg_mod.get_targets_at_step` returns `List[…]` and takes a `strategy` kwarg (`"next_read"` is what the fuzzer uses — see `fuzzer.py:1347`). `mem_val_mod.get_targets_at_step` also returns `List`. The others return `Optional[Target]`. The helper above handles both.

---

## TASK 3 — Re-run 7a-style smoke on V5 and verify the fix worked

After Tasks 1+2 are merged + tests pass, do a small local smoke (you already have `a4/tools/run_smoke_7a.py` machinery):

```bash
python -m a4.standalone.cli fuzz \
  --host workspace/output/target/release/risc0-host \
  --selector cTS_semantic_v2 --num 200 --seed 999 \
  --db a4/smoke_7a_v5_fixed.db --telemetry-level full \
  -- --in1 5 --in4 10
```

**Acceptance** (all of these must hold; show in your summary):
- `mutations` table: 200 rows (no skips because phantom arms are gone)
- `bandit_decisions` table: 200 rows, of which **>0 are `mode != "cold"`** (proves the bandit escaped cold-start and entered main TS loop). Realistic split: ~141 cold + ~59 adaptive/floor.
- `arm_state_snapshot` final rows: exactly **47 arms** (not 53), all with `pulls > 0`
- No regression in V1–V4 (re-run them too at N=20 to confirm `kindUCB/kindTS` paths still work; their `update()` call already exists for the kind-only path, so this is just guarding against changes).

If you see `mode != "cold"` count = 0, something is still wrong — escalate before continuing.

---

## TASK 4 — Rewrite `verify_mutation_semantics.py` against the mutation hook stdout — **G2 blocker**

This is the actual 7c work. The current verifier is structurally wrong (see report §2). The replacement parses the mutation hook's own `<a4_<kind>_mod>` JSON lines, which are emitted **after** the mutation runs and contain `old_*` / `new_*` ground truth.

**Spec**: see report §2.6 and the proof table in §2.5. The 4 tested samples (`LOAD_VAL_MOD id=29`, `STORE_OUT_MOD id=116`, `INSTR_TYPE_MOD id=109`, `MEM_VAL_MOD id=81`) should re-pass under the new verifier. All 24 should pass.

**Implementation sketch**:

```python
KIND_TAGS = {
    "COMP_OUT_MOD":        ("a4_comp_out_mod",        "txn_idx", "word"),
    "LOAD_VAL_MOD":        ("a4_load_val_mod",        "txn_idx", "word"),
    "STORE_OUT_MOD":       ("a4_store_out_mod",       "txn_idx", "word"),
    "MEM_VAL_MOD":         ("a4_mem_val_mod",         "txn_idx", "word"),
    "PRE_EXEC_REG_MOD":    ("a4_pre_exec_reg_mod",    "txn_idx", "word"),
    "INSTR_TYPE_MOD":      ("a4_instr_type_mod",      None,      ("major","minor")),
    "INSTR_WORD_MOD_FULL": ("a4_instr_word_mod",      None,      "word"),
    "INSTR_WORD_MOD_SUR":  ("a4_instr_word_mod",      None,      "word"),
}

def verify_sample(host, host_args, sample):
    cfg_path = write_config(sample["config"])
    env = {**os.environ, "A4_MUTATION_CONFIG": str(cfg_path),
                          "CONSTRAINT_CONTINUE": "1"}
    result = subprocess.run([host] + host_args, capture_output=True,
                            text=True, env=env, timeout=120)
    output = result.stdout + result.stderr
    tag, txn_field, change_field = KIND_TAGS[sample["kind"]]
    m = re.search(rf'<{tag}>([^<]+)</{tag}>', output)
    if not m:
        return False, f"no <{tag}> emitted — mutation hook didn't run for this sample"
    j = json.loads('{' + m.group(1).split('{', 1)[1])
    # Step must match
    if j.get("step") != sample["step"]:
        return False, f"hook step={j.get('step')} != sample step={sample['step']}"
    # Compare old vs new
    if change_field == "word":
        if j["new_word"] != sample["mutated_value"]:
            return False, f"hook new_word={j['new_word']} != sample mutated_value={sample['mutated_value']}"
        return True, f"old_word={j['old_word']} new_word={j['new_word']} at txn_idx={j.get('txn_idx')}"
    if change_field == ("major", "minor"):
        cfg = sample["config"]
        if j["new_major"] != cfg.get("major", j["new_major"]):
            return False, f"hook new_major={j['new_major']} != config major={cfg.get('major')}"
        if j["new_minor"] != cfg.get("minor", j["new_minor"]):
            return False, f"hook new_minor={j['new_minor']} != config minor={cfg.get('minor')}"
        return True, f"old={j['old_major']}/{j['old_minor']} new={j['new_major']}/{j['new_minor']}"
    return False, f"unsupported change_field {change_field}"
```

(There may be `byte_addr` cross-checks worth adding for STORE_OUT_MOD and MEM_VAL_MOD — config's `_info.memory_byte_addr` should equal `j["addr"] * 4` for those kinds. Optional but cheap.)

**Acceptance**: re-run the 24 stratified samples from V5's smoke DB; gate is **24/24 PASS**. Save to `a4/docs/cloud1/composer/PHASE_7C_SEMANTIC_RESULTS_v2.json` (don't overwrite the original — we want both for the audit trail). G2 is then resolved internally and Phase 7c can be marked ✅.

---

## TASK 5 — Diagnose `compressed_global_coverage = 0` (smaller, do after 1–4)

Across **all 5** 7b variants the `compressed_global_coverage` table is empty, despite `global_failures` having 291–611 rows per variant. Two candidates (report §1.5):

1. Plumbing — `A4_FAMILY_RESIDUE=1` isn't reaching the host on the v2 bandit path.
2. Empty residues — Hook 3 fires but always emits `"nonzero": false` for this guest.

**One-shot diagnostic** (5 minutes):

```bash
grep -c '<a4_family_residue ' a4/runs/pos_smoke_7b/.../*.log
grep -c '<a4_family_detail '  a4/runs/pos_smoke_7b/.../*.log
grep -c '"nonzero":true'      a4/runs/pos_smoke_7b/.../*.log
```

If counts 1+2 are zero → plumbing bug (find which path in fuzzer.py doesn't go through `run_a4_mutation`). Otherwise count 3 will tell us how often we see real signal — if it's 0 across all variants, document as a guest-selection limitation (G3 lens) and either pick a different guest for Phase 8 or accept the gate as informational-only.

---

## Order of operations

1. Stop 7c.
2. Tasks 1 + 2 + tests (1 commit, or 2 small ones — your call).
3. Task 3 (V5 smoke proves both fixes work end-to-end).
4. Open Tasks 1+2+3 as one Opus review item; do NOT start Task 4 until Opus signs off on the bandit fixes.
5. Task 4 (verifier rewrite + 7c re-run on the **existing** broken-V5 DB or a fresh fixed-V5 DB — either is fine for proving the verifier works; sample is random anyway).
6. Task 5 (compressed_global diagnostic) — last, can run while waiting for review.

## What to put in your next summary

- Commit SHAs for Tasks 1, 2, (3 if any code), 4.
- For Task 3: the 3 acceptance bullet results (mutations row count, `mode != "cold"` count, arm count).
- For Task 4: the 24/24 result + path to the new JSON.
- For Task 5: the three grep counts and which branch (plumbing vs guest).

Open questions stay in `composer/PROPOSED_DECISIONS.md` as usual.
