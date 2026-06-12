# C1 — Pilot Campaign (composer spec)

**Goal of C1:** run **both fuzzers** across the **6 aligned kinds** on the **realistic c0/c1 guest** at
**small N**, producing the *first real* category distributions (target & fail) and outcome-class
distributions — while (a) **fixing + validating the outcome classifier** (close the C0 gap) and
(b) **measuring throughput** to size C2. This is a pilot: the deliverable is a *trustworthy pipeline +
first numbers + runtime*, not final statistics.

**Hard isolation:** all new code under `thesis_side_experiments/bias_campaign/`. Drive the prebuilt
**production host** `workspace/output/target/release/risc0-host` (read/invoke-only). Reuse `a4/`
parsers + mutation creators read-only. Confirm production host sha256/mtime unchanged at the end.

---

## 0. Prerequisites (do these first)

### 0.1 Fix the outcome classifier (`classify.py`) — the C0 review finding
The minimal host panics at `main.rs:106` on any prove `Err`; that is **not** a prover crash.
- Define `prover_crash` = a `panicked at` whose path is **prover-internal**: contains any of
  `preflight.rs`, `/witgen/`, `risc0/circuit`, `risc0/zkp`. Keep `preflight_crash` as the subset whose
  path contains `preflight.rs`.
- A panic whose path contains `main.rs` (host harness) is **NOT** a crash — fall through to the
  failure/residue/verifier-based classes.
- New precedence:
  1. `PREFLIGHT_CRASH` — `preflight_crash`
  2. `OTHER_CRASH` — `prover_crash` (non-preflight) **and** 0 `<constraint_fail>`
  3. `CONSTRAINT_REJECT` — ≥1 `<constraint_fail>`
  4. `ACCEPTED` — injected and verifier success (record even when failures>0: see below)
  5. `GLOBAL_REJECT` — 0 local fails, global residue/family nonzero
  6. `VERIFY_REJECT` — proof produced, 0 fails, 0 residue, verifier failed (no crash)
  7. `NO_INJECTION` — target step had no `<fault>`
  8. `VALID_NO_SIGNAL` — else
- Always set `verifier_success` independently on `RunOutcome` (already present); the analysis layer must
  flag any run with `injected and verifier_success` as a **soundness escape** regardless of
  `outcome_class` (so an accepted-but-faulted run is never masked under `CONSTRAINT_REJECT`).
- **Determine production-host error behavior empirically:** run one Arguzz inject and one A4 mutation on
  the c0/c1 host that are *known* to reject; record whether the host returns cleanly or panics, and at
  what path. Bake the finding into the classifier and note it in the report.

### 0.2 Guest site map (`guest_sites.py`)
From **one** `--trace` baseline run of the c0/c1 host (`--in1 5 --in4 10`), parse `<trace>` lines
(`step, pc, instruction, assembly`) and `<fault>`/cycle info to produce:
- `steps`: list of `{step, pc, instruction, asm, class}` where `class ∈ {compute, load, store, branch,
  other}` (derive `class` from the decoded `instruction`/assembly).
- **Per-kind eligible step lists** (Arguzz only fires a kind in the matching instruction handler):
  - `COMP_OUT_MOD` → compute; `LOAD_VAL_MOD` → load; `STORE_OUT_MOD` → store;
  - `PRE_EXEC_REG_MOD`, `PRE_EXEC_MEM_MOD`, `INSTR_WORD_MOD` → any step.
- **Arguzz↔A4 step offset** for this guest (we saw +2 on minimal_add: Arguzz 187 / A4 185); confirm and record.
Cache to `artifacts/c1/guest_sites.json`.

---

## 1. Pilot configuration
| Param | Value |
|---|---|
| Guest / host | c0/c1 differential guest via `workspace/output/.../risc0-host`, args `--in1 5 --in4 10` |
| Aligned kinds | A4: `PRE_EXEC_REG_MOD, COMP_OUT_MOD, LOAD_VAL_MOD, STORE_OUT_MOD, MEM_VAL_MOD, INSTR_WORD_MOD_FULL` ↔ Arguzz: `PRE_EXEC_REG_MOD, COMP_OUT_MOD, LOAD_VAL_MOD, STORE_OUT_MOD, PRE_EXEC_MEM_MOD, INSTR_WORD_MOD` |
| N per kind per fuzzer | **50** (pilot) |
| Seeds | fixed list `range(50)` (recorded); reused identically per kind for reproducibility |
| Sampling | Arguzz: random eligible step per (kind,seed) from `guest_sites`; A4: a4 mutation creators pick valid target per kind (skip→retry, max 10) |
| Env (both) | `CONSTRAINT_CONTINUE, A4_COVERAGE_TOUCH, A4_COVERAGE_TOUCH_VERBOSE, A4_FAMILY_RESIDUE, A4_GLOBAL_RESIDUE` (Arguzz also via host `set_injection`→`FAULT_INJECTION_ENABLED`) |

---

## 2. Storage — one shared DB (refines PLAN §1)
Both runners write **one** `artifacts/c1/pilot.db` (SQLite) — our own schema, `a4/` untouched. (We drive
A4 via our `run_a4` + a4's mutation creators, **not** A4's `CoverageDB`, so capture is uniform.)
- `runs(run_id, fuzzer, guest, kind, seed, inject_step, target_desc, outcome_class,
   constraint_fail_count, fail_L1, fail_L2, fail_ACCUM, global_any, global_families_json,
   target_L1, target_L2, target_ACCUM, verifier_success, injected, soundness_escape, panic_loc,
   runtime_ms, raw_log_path)`
- `failures(run_id, constraint_type, constraint_loc, cycle, step, pc, major, minor, value, full_loc, phase, category)`
- `global_failures(run_id, family, address)`
Archive each run's raw stdout+stderr to `artifacts/c1/logs/<fuzzer>_<kind>_<seed>.txt` (gzip ok).

---

## 3. Deliverables (under `bias_campaign/`)
1. `classify.py` — updated per §0.1 (+ re-run C0 cases to confirm no regression).
2. `guest_sites.py` — §0.2.
3. `run_a4.py` — extend C0 version: given `(kind, step)`, build a config via the a4 mutation **creator**
   for that kind (reuse `a4.standalone.mutations`), run with full env, classify + categorize (incl.
   target categories from verbose touch), return a row.
4. `run_arguzz.py` — extend C0 version: capture target categories from verbose touch too.
5. `campaign_db.py` — schema + insert helpers (§2).
6. `pilot.py` — driver: for each fuzzer × kind, loop N seeds, sample eligible step, run, write DB.
   Parallelize (process/thread pool, ~4–8 workers); record per-run `runtime_ms`.
7. `analyze_pilot.py` + `artifacts/c1/C1_REPORT.{md,json}` — compute & emit §4.

---

## 4. Analysis output (C1_REPORT)
Per **fuzzer × kind** (and pooled per fuzzer):
- **Outcome-class distribution** (counts + %): which of the 8 classes occurred.
- **FAIL category distribution:** counts & share in {L1, L2, ACCUM, G} over rejecting runs.
- **TARGET category distribution:** mean {L1, L2, ACCUM} touched per run.
- **Reachability** = 1 − P(`PREFLIGHT_CRASH`+`OTHER_CRASH`); **detection rate** = P(any reject | reached).
- **Soundness escapes:** count of `injected and verifier_success`.
- Headline contrast table: A4 vs Arguzz fail-mass in L1 / L2 / G, per kind.
- Throughput: runs/min, mean `runtime_ms` by outcome, projected wall-time for C2 at N=500/1000.

---

## 5. Acceptance gate
1. **Classifier fix validated:** C0's 4 cases still classify correctly under the new rules; AND the
   pilot **observes ≥5 of the 8 outcome classes** with ≥1 hand-verified example each (read the raw log,
   confirm the class matches the tags). Explicitly demonstrate that a host `main.rs` panic with failures
   is `CONSTRAINT_REJECT`, and (if it occurs) a global-only rejection is `GLOBAL_REJECT`, not `OTHER_CRASH`.
2. **Both fuzzers run all 6 aligned kinds** on the c0/c1 guest; per-kind N met (or documented skips with
   reason, e.g. no eligible step).
3. **Reachability sanity:** A4 reach-rate ≈ 100%; Arguzz shows a nonzero `PREFLIGHT_CRASH`/`OTHER_CRASH`
   rate on at least the register/compute kinds (consistent with C0).
4. **Category sanity:** A4 fail-mass concentrates in L2+G for `PRE_EXEC_REG_MOD` (matches M2/C0);
   distributions populated for every kind.
5. **Determinism spot-check:** 3 runs/fuzzer re-executed → identical outcome + category counts.
6. **Reproducibility:** seeds, kinds, host sha256, git rev, guest args recorded in `C1_REPORT.json`.
7. **Isolation:** production host sha256/mtime unchanged; nothing outside `bias_campaign/` modified.

## 6. Report back to Opus (before C2)
- The headline A4-vs-Arguzz fail-category table (L1/L2/G) per kind + outcome-class distributions.
- The empirical production-host error behavior + the final classifier crash rule.
- Which outcome classes were observed (and any not seen) + the hand-verified examples.
- Reachability/crash rates per kind; soundness-escape count.
- Throughput + projected C2 wall-time.
- Any kind with no eligible steps / target-selection issues, and any category that needed a rule tweak.
```
Reproduce: cd /root/arguzz && python3 thesis_side_experiments/bias_campaign/pilot.py && \
           python3 thesis_side_experiments/bias_campaign/analyze_pilot.py
```
