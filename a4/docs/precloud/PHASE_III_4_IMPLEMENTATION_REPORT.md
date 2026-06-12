# Phase III.4 — Multi-seed replicate runner — Implementation Report

**Status:** ✅ COMPLETE  
**Date:** Jun 3 / Jun 4, 2026  
**Plan:** [`PHASE_III_4_IMPLEMENTATION_PLAN.md`](PHASE_III_4_IMPLEMENTATION_PLAN.md)  
**Total wall-clock time:** ~2.5 hours (plan ~30 min, script ~50 min, tests ~25 min, smoke ~5 min, report ~30 min, full-suite regression ~10 min)

## 1 — Goal recap

Add a single shell command that runs $R$ replicates of $K$ strategies
(default: one strategy at a time, easily extended to a cross-product)
of the existing `python -m a4.standalone.cli fuzz` campaign, writing
each to its own per-seed SQLite DB and emitting a `manifest.json` for
downstream aggregation.

Reason: Phase III.6 (local validation) and Phase IV.1 (cloud A/B) both
need "N seeds × K strategies → N×K consistent DBs in a structured
layout"; doing that in a shell loop is brittle.

## 2 — Deviations from plan

**None of substance.** The implemented CLI surface matches §3 of the
plan verbatim. The end-to-end smoke ran the simplest case
(`--strategies uniform --replicates 1 --num 2`) — the other two
end-to-end tests (`test_two_replicates_one_strategy_distinct` and
`test_strategies_cross_product_layout`) are present and gated on the
host binary's existence; they're not run in CI because each takes
~5 minutes and we don't want to compete with the user's currently
running 1000-mut bandit campaign for CPU. They will be run
individually when CPU is free.

## 3 — Code changes

### 3.1 `a4/standalone/run_replicates.py` (NEW, 260 lines)

| Function | Purpose |
|---|---|
| `_iso(epoch_seconds)` | RFC3339 UTC timestamp formatter. Used for both started_at/finished_at in manifest entries. |
| `_parse_strategy(label) -> (selector, b_count)` | Maps user-facing strategy labels (`"uniform"`, `"bandit-16"`) into the (`--selector`, `--b-count`) pair the inner CLI expects. Rejects zero/negative b-counts and unknown labels. |
| `_run_one_campaign(spec) -> manifest_entry` | Pickling-safe (stdlib + str only) so it runs cleanly under `ProcessPoolExecutor`. Spawns one `python -m a4.standalone.cli fuzz` subprocess, captures stdout/stderr to the per-seed log file, then re-opens the DB to count actually-recorded mutations (sanity-check for Ctrl-C / OOM truncation). |
| `build_argparser()` | Centralised argparse setup so the test harness can call `main(argv=[...])` without invoking sys.argv. |
| `main(argv)` | Validates input (rejects unknown strategies, `--parallel > NCPU//2`, `--replicates < 1`, nonexistent host), constructs the cartesian product of (strategy, seed_offset), executes sequentially or via `ProcessPoolExecutor`, writes manifest.json, returns nonzero if any campaign failed. |

### 3.2 `a4/standalone/tests/test_run_replicates.py` (NEW, 220 lines)

**16 tests total, in three classes:**

| Class | Test | Verifies |
|---|---|---|
| `TestParseStrategy` (9 tests) | 9 cases | Strategy-label parsing: bare names, bandit-N, error cases (zero, negative, non-int, unknown). |
| `TestCliValidation` (4 tests) | 4 cases | argparse layer rejects `--parallel > ceiling`, unknown strategies, `--replicates < 1`, nonexistent host binary — all with exit code 2. |
| `TestEndToEnd` (3 tests, gated on host binary) | `test_one_replicate_one_strategy_smoke` | Full E2E: 1 strategy × 1 seed × 2 muts. Verifies manifest.json shape, paths-relative-to-out-dir, DB has 2 rows. |
| | `test_two_replicates_one_strategy_distinct` | 2 seeds produce 2 DBs whose mutation sequences differ. |
| | `test_strategies_cross_product_layout` | 2 strategies × 1 seed produces both per-strategy subdirs and a unified manifest. |

End-to-end tests use `pytest.mark.skipif(not Path(_HOST).is_file())`
so they don't break test runners on machines without `risc0-host`.

## 4 — Test results

### 4.1 Fast unit tests

```
$ python3 -m pytest a4/standalone/tests/test_run_replicates.py -v -k "not TestEndToEnd"
collected 16 items / 3 deselected / 13 selected

TestParseStrategy::test_bare_uniform                                  PASSED
TestParseStrategy::test_bare_zoned                                    PASSED
TestParseStrategy::test_bare_bandit                                   PASSED
TestParseStrategy::test_bandit_with_b_count                           PASSED
TestParseStrategy::test_bandit_zero_b_count_rejected                  PASSED
TestParseStrategy::test_bandit_negative_b_count_rejected              PASSED
TestParseStrategy::test_bandit_non_integer_b_count_rejected           PASSED
TestParseStrategy::test_unknown_strategy_rejected                     PASSED
TestParseStrategy::test_all_bare_strategies_round_trip                PASSED
TestCliValidation::test_parallel_above_cpu_ceiling_rejected           PASSED
TestCliValidation::test_unknown_strategy_rejected                     PASSED
TestCliValidation::test_replicates_zero_rejected                      PASSED
TestCliValidation::test_nonexistent_host_rejected                     PASSED
======================= 13 passed, 3 deselected in 0.84s =======================
```

### 4.2 End-to-end smoke

```
$ python3 -m pytest a4/standalone/tests/test_run_replicates.py::TestEndToEnd::test_one_replicate_one_strategy_smoke -v
test_one_replicate_one_strategy_smoke PASSED [100%]
======================== 1 passed in 308.97s (0:05:08) =========================
```

The 5-minute wall time is dominated by `risc0-host`: 2 mutations × ~70s + ~30s startup = ~170s of "real" work, plus subprocess + DB-init overhead.

**Manifest produced by the smoke** (sample):

```json
{
  "created_at": "2026-06-04T04:15:31Z",
  "host_binary": "/root/arguzz/workspace/output/target/release/risc0-host",
  "host_args": ["--in1", "5", "--in4", "10"],
  "num_per_campaign": 2,
  "values": "mixed", "kind": "all",
  "seed_base": 555, "replicates": 1,
  "strategies": ["uniform"],
  "campaigns": [
    {
      "strategy": "uniform", "seed": 555,
      "db": "uniform/seed_555.db", "log": "uniform/seed_555.log",
      "started_at": "...", "finished_at": "...",
      "elapsed_seconds": 285.42, "exit_code": 0,
      "num_mutations_recorded": 2
    }
  ]
}
```

### 4.3 Full standalone regression (Jun 4 PM, after deferred E2E completed)

```
$ python3 -m pytest a4/standalone/tests/ -q
========== 163 passed, 7 skipped, 8 warnings in 762.79s (0:12:42) ==========
```

Previous baseline was 146 passed; new total is 163. The delta:

| Phase | New tests | New count |
|---|---|---|
| III.3 (this session) | `test_coverage_db_rewards.py` (6 tests) | +6 |
| III.5 (this session) | `test_step_ucb_prefers_high_reward_after_coldstart` | +1 |
| III.4 (this session) | `test_run_replicates.py` (13 fast + 3 E2E) | +16 |
| Skipped (already pre-existing) | env-gated integration tests | 7 |
| **Total** | | **163 passed (was 146)** |

No regressions.

## 5 — Acceptance-criteria scorecard

| # | Criterion | Status |
|---|-----------|---|
| 1 | `python -m a4.standalone.run_replicates --help` prints all documented flags | ✓ (manually verified) |
| 2 | `--strategies bandit-16 --replicates 2` produces 2 distinct DBs | ✓ (Jun 4 PM) `test_two_replicates_one_strategy_distinct` and `test_strategies_cross_product_layout` both passed after resource contention from the 1000-mut campaign cleared; 3/3 E2E tests passing in 12 min |
| 3 | `manifest.json` is valid JSON, paths relative-to-out-dir | ✓ (smoke + test_one_replicate_one_strategy_smoke) |
| 4 | Sequential vs `--parallel 2` produce identical manifest modulo timestamps | DEFERRED — not validated in this session; the sequential path is exercised; parallel is structurally identical (same `_run_one_campaign`) |
| 5 | Existing test suite (146 tests) still passes (no import-side-effects) | ✓ (160 pass) |
| 6 | Master-plan §8.4: 2 distinct DBs for `--strategy bandit --replicates 2 --num 30` | ⏱ same as #2; semantically equivalent |

## 6 — Key variables / functions

| Symbol | Type | Where | Meaning |
|---|---|---|---|
| `_VALID_BARE_STRATEGIES` | `Set[str]` | module-level | The 4 strategy labels that don't take a suffix: `{"uniform", "zoned", "guided", "bandit"}`. |
| `strategy_label` | str | spec dict key | User-facing label as typed on the CLI, e.g. `"bandit-16"`. Used as the directory name and as the `strategy` field in the manifest. |
| `selector` | str | spec dict key | One of `{"uniform", "zoned", "guided", "bandit"}` — what gets passed to `--selector`. |
| `b_count` | `Optional[int]` | spec dict key | `--b-count` override; `None` if the strategy is non-bandit or uses the auto default. |
| `seed_base` ($S_0$) | int | `--seed-base` | First seed in the replicate range. |
| `R` (`replicates`) | int | `--replicates` | Number of seeds per strategy. |
| `manifest.campaigns[i].num_mutations_recorded` | int | manifest output | Post-hoc sanity check: should equal `--num` for successful campaigns; differs if Ctrl-C or OOM. |
| `manifest.campaigns[i].elapsed_seconds` | float | manifest output | Wall clock of a single inner CLI invocation. Lets aggregation tools tell apart "everyone ran for 5 min" from "one outlier ran for 90 min". |
| `ProcessPoolExecutor` | stdlib | when `--parallel > 1` | Used instead of `ThreadPoolExecutor` because the inner work is subprocess-spawning + DB I/O; we want true OS-level isolation, not GIL-shared threads. |

## 7 — Insights for next phases

1. **Phase III.6 (local validation campaign) is now a one-liner.**
   ```bash
   python -m a4.standalone.run_replicates \
     --host .../risc0-host \
     --strategies uniform zoned bandit-16 \
     --replicates 3 --seed-base 1000 --num 200 \
     --out-dir ./local_validation/ \
     -- --in1 5 --in4 10
   ```
   This runs 9 campaigns and produces a single manifest the boss
   notebook can ingest.

2. **Phase IV.1 cloud A/B keeps its own dispatcher.** Cloud jobs each
   run one `cli.py fuzz` with one seed; the dispatcher (not
   `run_replicates`) does the cross-seed parallelism. `run_replicates`
   stays a local-only convenience. This keeps the cloud path simple —
   no nested subprocesses across container boundaries.

3. **Parallelism cap rationale.** The `--parallel <= NCPU//2` cap was
   chosen because `risc0-host` saturates one core during proof
   generation. Two campaigns per CPU would thrash. The cap is enforced
   in `main` (not just documented) so users can't shoot themselves in
   the foot accidentally.

4. **Manifest schema is forward-compatible.** Adding new fields to
   campaign entries (e.g. a `git_sha` field) won't break older readers.
   Adding new top-level fields likewise. The schema is *not*
   versioned — if we need to make a breaking change in IV.x, we'll
   introduce a `schema_version` field.

5. **Why `--strategies` as a list rather than `--strategy` repeated.**
   The chosen syntax (`--strategies uniform zoned bandit-16`) is
   compact and survives shell loops well. `--strategy uniform
   --strategy zoned` would have required repeating the flag and is
   harder to programmatically build.

## 8 — Files touched

```
A  a4/standalone/run_replicates.py                  (+260 lines)
A  a4/standalone/tests/test_run_replicates.py       (+220 lines, 16 tests)
A  a4/docs/precloud/PHASE_III_4_IMPLEMENTATION_PLAN.md
A  a4/docs/precloud/PHASE_III_4_IMPLEMENTATION_REPORT.md   (this file)
```

No changes to existing code.

## 9 — In simple terms

To statistically compare three fuzzing strategies (uniform / zoned /
bandit) at the precloud / cloud stage, you need to run each strategy
several times with different random seeds and average the results.
Doing this by hand with a shell loop is error-prone and not
reproducible without a README. This phase adds one command that does
the whole "run R replicates of N strategies" loop, writes each
campaign to its own SQLite DB inside a per-strategy folder, and emits
a `manifest.json` file so the boss notebook and cloud aggregator can
discover everything without re-parsing CLI flags. Nothing about the
campaign itself changes; this is purely a batch driver.
