# Phase III.4 — Multi-seed replicate runner — Implementation Plan

**Status:** PLAN  
**Created:** Jun 4, 2026 (evening session after III.3 completion)  
**Depends on:** Phase III.2 (selector trio: uniform / zoned / bandit — DONE), Phase III.3 (reward-row persistence — DONE so cross-replicate aggregation is meaningful)  
**Blocks:** Phase III.6 (local validation campaign uses this), Phase IV.1 (cloud A/B campaign also uses this — locally it's a wrapper; in cloud each job is a single seed and the dispatcher provides the cross-seed parallelism)

## 1 — Goal

Today: one `python -m a4.standalone.cli fuzz` invocation = one campaign
= one seed. To execute the master-plan §10 local validation
(3 strategies × 3 seeds × 200 muts = 9 campaigns) the user has to write
their own shell loop — error-prone and not reproducible without a
README.

We add a thin Python wrapper `a4/standalone/run_replicates.py` that:

1. Takes $R$ replicates × $S_0$ seed base.
2. For each $i \in [0, R)$, shells out to the existing
   `a4.standalone.cli fuzz` with `--seed = $S_0 + i$`, writing to
   `--db <out-dir>/seed_<S_0+i>.db` and tee-ing stdout to
   `<out-dir>/seed_<S_0+i>.log`.
3. Optionally runs replicates sequentially (default) or in parallel
   (`--parallel N` to bound concurrency; the host binary is
   single-CPU-bound so $N \le \text{NCPU}/2$ is the safe ceiling).
4. Writes a manifest `<out-dir>/manifest.json` so the boss notebook /
   cloud aggregator can discover the $R$ DBs without re-parsing CLI
   arguments.

Bonus: we add **one** flag `--strategies` so you can do
"3 strategies × 3 seeds = 9 campaigns" in **one** command:

```bash
python -m a4.standalone.run_replicates \
  --host .../risc0-host \
  --strategies uniform zoned bandit-16 \
  --replicates 3 --seed-base 1000 \
  --num 200 \
  --out-dir ./local_validation/ \
  -- --in1 5 --in4 10
```

This produces:

```
local_validation/
├── manifest.json
├── uniform/
│   ├── seed_1000.db   seed_1000.log
│   ├── seed_1001.db   seed_1001.log
│   └── seed_1002.db   seed_1002.log
├── zoned/
│   └── ...
└── bandit-16/
    └── ...
```

## 2 — What this phase is NOT

- **NOT** an aggregation step. III.4 only **produces** the DBs in a
  consistent layout. The aggregation that consumes them (cumulative
  curves, ANOVA across replicates, etc.) is Phase IV.2.
- **NOT** the cloud dispatcher. Each cloud Cloud Run Job is a single
  campaign with a single `--seed`. The cross-seed parallelism in cloud
  is done by the dispatcher, not by `run_replicates.py`. `run_replicates`
  is local-only.
- **NOT** a refactor of `cli.py`. The fuzz subcommand stays as-is.
  This script is purely a wrapper.

## 3 — CLI surface (final)

```
usage: run_replicates.py [-h] --host HOST [--num NUM] [--replicates R]
                         [--seed-base S0] [--strategies S [S ...]]
                         [--out-dir OUT_DIR] [--parallel N]
                         [--values VALUES] [--kind KIND]
                         [host_args ...]

positional:
  host_args             Forwarded to risc0-host (after --).

required:
  --host HOST           Path to risc0-host binary.

per-campaign config (same defaults as cli.py fuzz):
  --num NUM             Mutations per campaign (default 200).
  --kind KIND           Mutation kind (default "all").
  --values VALUES       Value strategy (default "mixed").

replicate / strategy config (NEW):
  --replicates R        Number of seeds per strategy (default 3).
  --seed-base S0        First seed; subsequent are S0, S0+1, ..., S0+R-1
                        (default 1000).
  --strategies S [S]    One or more from {uniform, zoned, bandit-16, bandit-32,
                        bandit-64}. The bandit suffix is the --b-count.
                        Default: uniform.
  --out-dir OUT_DIR     Directory to write per-strategy subfolders and
                        manifest.json. Created if missing. Must be empty
                        or contain only this script's outputs. Default
                        ./replicates_out/.
  --parallel N          Run up to N campaigns concurrently (default 1
                        = sequential). N <= os.cpu_count() // 2 enforced.
```

### 3.1 Why `--strategies` accepts `bandit-16`/`bandit-32` not `bandit --b-count 16`

The user-facing knob "what to compare" is a single label. Encoding the
b-count in the label (a) keeps the shell command short, (b) embeds
into output directory names cleanly (`bandit-16/`), and (c) maps
naturally to a strategy id in `manifest.json` and downstream aggregation.

Internally, `bandit-16` is parsed into `(selector="bandit", b_count=16)`
which becomes `--selector bandit --b-count 16` on the inner CLI call.
A bare `bandit` is also accepted and means `--selector bandit` with the
arm-universe's default b_count (computed from N).

## 4 — Manifest schema

`<out-dir>/manifest.json`:

```json
{
  "created_at": "2026-06-04T03:55:01Z",
  "host_binary": "/root/arguzz/workspace/output/target/release/risc0-host",
  "host_args": ["--in1", "5", "--in4", "10"],
  "num_per_campaign": 200,
  "values": "mixed",
  "kind": "all",
  "seed_base": 1000,
  "replicates": 3,
  "strategies": ["uniform", "zoned", "bandit-16"],
  "campaigns": [
    {
      "strategy": "uniform",
      "seed": 1000,
      "db": "uniform/seed_1000.db",
      "log": "uniform/seed_1000.log",
      "started_at": "...",
      "finished_at": "...",
      "exit_code": 0,
      "num_mutations_recorded": 200
    },
    ...
  ]
}
```

Paths in `db` / `log` are **relative to `out-dir`** so the directory
can be moved/zipped without breaking.

`num_mutations_recorded` is the actual count in the DB (a sanity check
that the campaign wasn't truncated by Ctrl-C / OOM); it's filled in
after the inner CLI returns by opening the DB and counting.

## 5 — Implementation sketch

```python
# a4/standalone/run_replicates.py

import argparse, json, os, sqlite3, subprocess, sys, time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import List, Tuple

_VALID_STRATEGIES = {"uniform", "zoned", "bandit", "bandit-16", "bandit-32", "bandit-64"}


def _parse_strategy(label: str) -> Tuple[str, int | None]:
    if label.startswith("bandit-"):
        return "bandit", int(label.split("-", 1)[1])
    return label, None


def _run_one_campaign(args: dict) -> dict:
    """
    Execute one inner CLI invocation. Returns a dict matching the
    manifest's `campaigns[i]` schema, with started_at/finished_at filled
    in. Designed to be safe under ProcessPoolExecutor.
    """
    cmd = [
        sys.executable, "-m", "a4.standalone.cli", "fuzz",
        "--host", args["host"],
        "--num", str(args["num"]),
        "--kind", args["kind"],
        "--values", args["values"],
        "--selector", args["selector"],
        "--seed", str(args["seed"]),
        "--db", args["db_abs"],
    ]
    if args["b_count"] is not None:
        cmd += ["--b-count", str(args["b_count"])]
    if args["host_args"]:
        cmd += ["--"] + args["host_args"]

    started_at = time.time()
    with open(args["log_abs"], "w") as f:
        rc = subprocess.call(cmd, stdout=f, stderr=subprocess.STDOUT)
    finished_at = time.time()

    n_mut = -1
    if Path(args["db_abs"]).exists():
        with sqlite3.connect(args["db_abs"]) as c:
            n_mut = c.execute("SELECT COUNT(*) FROM mutations").fetchone()[0]

    return {
        "strategy": args["strategy_label"],
        "seed": args["seed"],
        "db": args["db_rel"],
        "log": args["log_rel"],
        "started_at": _iso(started_at),
        "finished_at": _iso(finished_at),
        "exit_code": rc,
        "num_mutations_recorded": n_mut,
    }


def main():
    parser = argparse.ArgumentParser(...)
    # ... parse args ...
    args = parser.parse_args()

    if args.parallel > (os.cpu_count() or 1) // 2:
        sys.exit(f"--parallel {args.parallel} too high; ceiling is "
                 f"{(os.cpu_count() or 1) // 2}")

    out = Path(args.out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    # Build the cartesian product of (strategy, seed_offset).
    campaign_specs = []
    for strat_label in args.strategies:
        if strat_label not in _VALID_STRATEGIES:
            sys.exit(f"Unknown strategy: {strat_label}")
        selector, b_count = _parse_strategy(strat_label)
        strat_dir = out / strat_label
        strat_dir.mkdir(exist_ok=True)
        for i in range(args.replicates):
            seed = args.seed_base + i
            campaign_specs.append({
                "strategy_label": strat_label,
                "selector": selector,
                "b_count": b_count,
                "seed": seed,
                "host": args.host, "num": args.num, "kind": args.kind,
                "values": args.values, "host_args": args.host_args,
                "db_abs": str(strat_dir / f"seed_{seed}.db"),
                "log_abs": str(strat_dir / f"seed_{seed}.log"),
                "db_rel": f"{strat_label}/seed_{seed}.db",
                "log_rel": f"{strat_label}/seed_{seed}.log",
            })

    # Run.
    completed: List[dict] = []
    if args.parallel <= 1:
        for spec in campaign_specs:
            print(f"[run_replicates] starting {spec['strategy_label']} seed={spec['seed']}")
            completed.append(_run_one_campaign(spec))
    else:
        with ProcessPoolExecutor(max_workers=args.parallel) as ex:
            futures = {ex.submit(_run_one_campaign, s): s for s in campaign_specs}
            for fut in as_completed(futures):
                completed.append(fut.result())
        completed.sort(key=lambda d: (d["strategy"], d["seed"]))

    # Write manifest.
    manifest = {
        "created_at": _iso(time.time()),
        "host_binary": args.host, "host_args": args.host_args,
        "num_per_campaign": args.num, "values": args.values, "kind": args.kind,
        "seed_base": args.seed_base, "replicates": args.replicates,
        "strategies": list(args.strategies),
        "campaigns": completed,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))

    # Exit nonzero if ANY campaign failed.
    failed = [c for c in completed if c["exit_code"] != 0]
    if failed:
        print(f"[run_replicates] {len(failed)}/{len(completed)} campaigns failed:", file=sys.stderr)
        for c in failed:
            print(f"  {c['strategy']}/seed_{c['seed']}: exit {c['exit_code']}", file=sys.stderr)
        sys.exit(1)
```

## 6 — Tests (NEW: `test_run_replicates.py`)

Five tests, structured so the slow ones are gated behind a marker:

1. **`test_parse_strategy_label`** — pure unit; `bandit-16` → `("bandit", 16)`, `uniform` → `("uniform", None)`.
2. **`test_cli_argument_validation`** — `--parallel 9999` rejected; unknown strategy rejected.
3. **`test_one_replicate_one_strategy_smoke`** — runs `--strategies uniform --replicates 1 --num 2` and verifies the output directory layout: `uniform/seed_<N>.db` exists, `manifest.json` exists and parses, `manifest.campaigns[0].num_mutations_recorded == 2`.
4. **`test_two_replicates_one_strategy_distinct_dbs`** — runs `--replicates 2 --num 3`. Asserts the two DBs exist and differ (different `mutations.config_json` from different seeds, OR different `mutations.id` ordering after both have 3 rows — at minimum the file hashes differ).
5. **`test_strategies_cross_product`** — runs `--strategies uniform zoned --replicates 1 --num 2`. Asserts both `uniform/seed_*.db` and `zoned/seed_*.db` exist.

Tests 3-5 invoke the real `risc0-host` binary so they are gated:
```python
@pytest.mark.skipif(
    not Path("/root/arguzz/workspace/output/target/release/risc0-host").exists(),
    reason="risc0-host not built")
```

## 7 — Acceptance criteria

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | `python -m a4.standalone.run_replicates --help` prints all documented flags | manual |
| 2 | `--strategies bandit-16 --replicates 2 --num 5` produces two DBs whose `mutations.id` orderings differ (different selections under different seeds) | test 4 |
| 3 | `manifest.json` is valid JSON, contains one entry per (strategy, seed), and paths are relative-to-out-dir | test 3 |
| 4 | Sequential vs `--parallel 2` produce identical manifest (modulo timestamps) for the same inputs | manual cross-check; not gated |
| 5 | Existing test suite (146 tests) still passes (no import-side-effects) | `pytest a4/standalone/tests/ -x` |
| 6 | Master-plan §8.4 acceptance: 2 distinct DBs for `--strategy bandit --replicates 2 --num 30` | covered by test 4 (scaled down) |

## 8 — Risk + rollback

**Risk: LOW.** New file only. The existing `cli.py` is unmodified.

**Rollback:** delete `a4/standalone/run_replicates.py` and its test.

## 9 — Estimated effort

- `run_replicates.py` (~250 lines including docstrings): 1 hour
- 5 unit tests: 45 min  
- Sequential smoke verifying 2 replicates: ~3 min × 2 muts/replicate = quick
- Report: 20 min

**Total: ~2.5 hours.**

## 10 — In simple terms

To statistically compare two fuzzing strategies (say, "uniform sampling"
vs "the bandit with 16 buckets") you can't just run each once and
compare numbers — random seeds matter, and a single campaign can be
lucky or unlucky. The standard practice is "run each strategy $R$
times with different seeds and average". This phase adds a single
shell command that does that whole loop. It writes each replicate to
its own SQLite DB inside a per-strategy folder, plus a manifest file
that downstream analysis tools can read to discover what's in the
directory. Nothing about the campaign itself changes; this is just a
batch driver.
