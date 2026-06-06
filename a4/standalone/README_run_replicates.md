# `run_replicates.py` — multi-seed × multi-strategy local runner

One-line summary: orchestrates N `cli fuzz` campaigns across a Cartesian product of strategies × seeds, writes a structured `manifest.json` summarising what ran and where the outputs live.

## When to use

- **Local III.6 piggyback validation** (the file you're reading was written for that): replicate the bandit-16 result with uniform + zoned at matched N + seed.
- **Local regression** before pushing a change that touches the bandit or coverage code: replicate the run with the same (strategy, seed) you used yesterday and diff the outputs.
- **Smoke test of `cli.py fuzz` end-to-end** without writing a one-off script.

## What it does NOT do

- Does **not** target cloud (Cloud Run + GCS); use `a4/cloud/dispatch.py` for that.
- Does **not** parallelise within a single campaign (mutations are still sequential inside a `cli fuzz` invocation; only different `(strategy, seed)` pairs run in parallel).
- Does **not** do statistical aggregation; the manifest is a "what-ran-where" map only. Use `analyze_campaign.py` per DB, or the precloud-validation notebook for cross-strategy comparison.

## Quick start

```bash
# 3 strategies × 2 seeds × 250 muts, parallel-2
python -m a4.standalone.run_replicates \
  --host /root/arguzz/workspace/output/target/release/risc0-host \
  --strategies uniform zoned bandit \
  --replicates 2 --seed-base 1000 \
  --num 250 \
  --parallel 2 \
  --out-dir /root/arguzz/out_smoke/ \
  -- --in1 5 --in4 10
```

Produces:
```
out_smoke/
├── manifest.json
├── uniform/seed_1000.{db,log}   seed_1001.{db,log}
├── zoned/seed_1000.{db,log}     seed_1001.{db,log}
└── bandit/seed_1000.{db,log}    seed_1001.{db,log}
```

## CLI surface

| flag | meaning |
|---|---|
| `--host PATH` | risc0-host binary (must be executable) |
| `--strategies LIST` | space-separated: `uniform`, `zoned`, `bandit`, optionally `bandit-N` to pass `--b-count N` |
| `--replicates K --seed-base S` | run K replicates per strategy with seeds `S, S+1, ..., S+K-1` |
| `--num N` | mutations per replicate |
| `--parallel P` | max concurrent campaigns (capped by `NCPU//2` internally for safety) |
| `--out-dir DIR` | output root; subdirs created per strategy |
| `-- ARGS...` | passed verbatim as host args after `--` (e.g. `-- --in1 5 --in4 10`) |

## Manifest schema

```json
{
  "runner_version": "1",
  "started_at_utc": "...",
  "ended_at_utc":   "...",
  "host":  "/root/arguzz/workspace/output/target/release/risc0-host",
  "num":   1000,
  "strategies": ["uniform", "zoned"],
  "replicates": 1,
  "seed_base": 1234,
  "parallel": 2,
  "runs": [
    {
      "strategy": "uniform",
      "seed":     1234,
      "selector": "uniform",
      "b_count":  null,
      "db":       "uniform/seed_1234.db",
      "log":      "uniform/seed_1234.log",
      "exit_code": 0,
      "started_at_utc":  "...",
      "ended_at_utc":    "..."
    },
    ...
  ]
}
```

## Common pitfalls

- **CPU contention**: each `cli fuzz` spawns `risc0-host` which uses ~1 core. On 8-core boxes, `--parallel 4` is the recommended ceiling; the runner caps at `NCPU // 2` to leave headroom for analyze/notebook work.
- **Subprocess stdout is block-buffered**: the `.log` files start at 0 bytes and stay that way for ~1 min until the inspection phase prints its summary. Wait or look at the DB row count via `sqlite3 ... 'SELECT COUNT(*) FROM mutations'` to monitor progress.
- **Crashes propagate via exit code**: if `cli fuzz` raises, the runner records the exit code and the partial DB; it does NOT delete the output. Other replicates continue.
- **Reproducibility**: same (strategy, seed, num, host_args, binary sha) → same DB. If you change calibrated params or the binary, you get different mutation streams even at the same seed.

## See also

- `a4/standalone/cli.py fuzz --help` — what the runner actually invokes
- `a4/cloud/dispatch.py` — same idea, but submits to Cloud Run instead
- `a4/standalone/analyze_campaign.py` — single-DB post-hoc analysis
- `a4/notebooks/precloud_validation.ipynb` — cross-strategy gate-criteria computation
