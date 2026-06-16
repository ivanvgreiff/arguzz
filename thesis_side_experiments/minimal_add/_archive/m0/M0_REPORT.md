# M0 Report — Reproduce & Freeze Baseline

**Status:** PASS (automated gate)

## Production isolation
- Production host: `/root/arguzz/workspace/output/target/release/risc0-host`
- mtime unchanged after `./build.sh`: **True**

## Auto-derived add site
| Field | Value |
|-------|-------|
| Arguzz step | 187 |
| Arguzz pc | 2099232 (`0x00200820`) |
| Assembly | `add s0, a0, a1` |
| A4 step | 185 |
| A4 pc (next PC) | 2099236 (`0x00200824`) |
| cycle_idx | 15424 |
| major / minor | 0 / 0 |

Sanity: steps 185–186 are `li a0, 3` and `li a1, 4`.

## Instruction card (A4 step 185)
| txn_idx | reg | op | word | prev_word |
|---------|-----|----|------|-----------|
| 15056 | a0 | READ | 3 | 3 |
| 15057 | a1 | READ | 4 | 4 |
| 15058 | s0 | WRITE | 7 | 0 |

## Baseline determinism (2 runs, env={'CONSTRAINT_CONTINUE': '1', 'A4_COVERAGE_TOUCH': '1', 'A4_COVERAGE_TOUCH_VERBOSE': '1'})
- constraint_fail count: **0** / **0**
- local touch verbose set size: **1580** (identical across runs)
- accum touch verbose set size: **298** (identical across runs)
- local bitmap distinct buckets: **1565**
- accum bitmap distinct buckets: **294**

## Frozen artifacts
- `artifacts/m0/add_site.json`
- `artifacts/m0/instruction_card.json`
- `artifacts/m0/baseline_trace_deduped.txt`
- `artifacts/m0/step_185_dump.txt`
- `artifacts/m0/baseline_touch_run1.txt`
- `artifacts/m0/baseline_touch_run2.txt`
- `artifacts/m0/M0_REPORT.json`

## Opus review gate
M0 acceptance criteria met. Proceed to **M1** after Opus greenlight.
