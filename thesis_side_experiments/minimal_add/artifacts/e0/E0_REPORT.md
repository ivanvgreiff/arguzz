# E0 Report — Guest Rebuild + Site Derivation + Baseline

**Status:** PASS

Host: `/root/arguzz/thesis_side_experiments/minimal_add/target/release/thesis-minimal-host`
Arguzz→A4 step offset: **-2** (empirical, not assumed)

## Production isolation
- mtime unchanged after `./build.sh`: **True**

## Site card (five roles)

| Role | Arguzz step | A4 step | Assembly |
|------|-------------|---------|----------|
| load_x | 193 | 191 | `lw a2, 0(sp)` |
| load_y | 194 | 192 | `lw a1, 4(sp)` |
| add | 195 | 193 | `add a1, a1, a2` |
| store | 196 | 194 | `sw a1, 8(a0)` |
| read_back | 197 | 195 | `lw s0, 8(a0)` |

## Baseline determinism (2×, DEFAULT_ENV)
- constraint_fail: **0** / **0**
- global residue: **0** / **0**
- local touch verbose size: **1580** (identical 2×)
- accum touch verbose size: **298** (identical 2×)

## Frozen artifacts
- `artifacts/e0/site_card.json`
- `artifacts/e0/baseline_universe.json`
- `artifacts/e0/baseline_trace_deduped.txt`
- `artifacts/e0/E0_REPORT.json`
