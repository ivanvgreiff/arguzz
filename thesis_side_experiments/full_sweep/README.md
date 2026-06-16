# E5 full_sweep — per-mutation-type distribution study (Batch 2)

Sibling workspace to `minimal_add/` (Batch 1). Builds its **own** guest + host binary
under `target/`; never touches `workspace/output/` or the Batch-1 frozen host.

## Layout

| Path | Role |
|------|------|
| `build.sh` | Isolated release build (`CARGO_TARGET_DIR=./target`) |
| `host/`, `methods/` | Host + broad guest (see `methods/guest/src/main.rs`) |
| `frozen_host/` | Frozen E5 binary + SHA256 after E5-E0 |
| `host_guard.py` | Mtime/sha guard for external binaries |
| `run_e5_e0.py` | Baseline + one-time context capture |
| `sample_e5.py` | Enumerate N-per-type sample set |
| `run_e5.py` | POS dispatch (shardable across free nodes) |
| `compute_e5_stats.py` | Atoms → `e5_stats.json` + `DISTRIBUTIONS.md` |
| `a4_config_ext.py` | A4 config builders incl. `INSTR_TYPE_MOD` |
| `artifacts/e5/` | `context/`, `atoms/`, `raw/`, stats |

## Spec

See `../minimal_add/specs/E5_SPEC.md` and `../minimal_add/specs/EXAMPLE_PLAN.md` §G.

## Quick start (WSL)

```bash
cd thesis_side_experiments/full_sweep
python3 -c "from host_guard import snapshot_external; snapshot_external()"
./build.sh
python3 -c "from host_guard import snapshot_external, assert_external_unchanged, freeze_full_sweep_host; b=snapshot_external(); freeze_full_sweep_host(); assert_external_unchanged(b)"
python3 run_e5_e0.py
python3 sample_e5.py --n 20
```

## POS

User must reserve dedicated free node(s) via web calendar (`--allocation-duration 0`).
**Do not use** the user's 8 reserved nodes (`algofi`, `flare`, `gard`, `goracle`,
`octorand`, `opulous`, `polynize`, `zone`). Check live availability with
`pos nodes list` before reserving E5-only nodes.
