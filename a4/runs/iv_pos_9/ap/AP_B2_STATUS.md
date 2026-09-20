# AP.B2 Status — Toolchain Blocker & Path Forward

## Step 0 status — stage 1 DONE, stage 2 running

| Milestone | Status |
|-----------|--------|
| gen_zirgen (stage 1) | **DONE** — Opus native build, `bazel-bin/zirgen/Main/gen_zirgen` (~26 min) |
| codegen (stage 2) | **RUNNING** — native toolchain, log: `build_spike_stage2.log` |
| control-regen | queued after stage 2 |

**Toolchain fix (Opus + Composer):** drop `--config=bootstrap_linux_amd64`; use host gcc + `--spawn_strategy=local`. Conda-prune still required.

**Scripts updated:** `ap_zirgen_bazel_common.sh`, `ap_zirgen_build_spike.sh`, `ap_zirgen_regen.sh`, bootstrap `main.rs` (`ZIRGEN_AP_NATIVE_BAZEL=1`).

POS/external host: **contingency only** (OOM on link — stage 1 link succeeded).

## Where we are

```
0. build gen_zirgen + codegen   ← IN PROGRESS (isolated spike stage 1)
1. control-regen                  not started
2. honest-gate          [HARD]    not started
3. control-check/semantic-diff    not started (soft)
4. holed-regen                    not started
5. build --from-regen             not started
6. ap_b1_verify mutated-V0 [HARD] not started  ← first real IsRead test
7. ap_b2_replay bracket           not started
```

**Zero regenerated circuit artifacts to date.** All work so far = scaffolding + toolchain attempt.

---

## Actions taken (Opus recommendation B)

1. **Killed** stuck `control-check` (PID ~492441) and conda install (~497427, ~5 GB RAM, 3600s timeout).
2. **Committed** `witgen/mod.rs` → `6556e8d7` on `arguzz/b7-race-instrumentation` (A4_MUTATION_CONFIG safe from git churn).
3. **Started** `ap_zirgen_build_spike.sh --stage 1` after killing a blocking `bazel cquery` probe.

**Conda reality:** `rules_conda` in `zirgen/WORKSPACE` runs on the **first bazel target of any kind** — stage 1 does not bypass it. Killing the old control-check freed ~3 GB RAM (conda dropped from ~5 GB to ~1.8 GB RSS). The spike is now the single conda consumer; monitor `build_spike.log`.

---

## Agreement with Opus probability decomposition

| Gate | Opus estimate | Composer view |
|------|---------------|---------------|
| Toolchain (step 0) | ~75% | **Agree** — conda solve is the known failure mode; isolated spike makes diagnosis cheap |
| honest-gate (step 2) | ~85–90% | **Agree** — `RV32IM:v2rev2___` + self-consistent regen is strong signal |
| mutated-V0 (step 6) | ~55–70% | **Agree** — never tested with genuine holed circuit; global LogUp residual is real uncertainty |
| **Net working IsRead hole** | ~40% | **Agree** — product of independent gates |
| **Project success (some planted target)** | ~70–80% | **Agree** — Seam B fallback documented |

**Key reframe (Opus):** Regen is what runs the experiment. Until step 6, the 55–70% number doesn't move.

---

## Fallback: Seam B (pre-staged)

If mutated-V0 fails after genuine holed regen (global permutation guards read value):

- **Seam B:** remove decode binding (`DecodeInst`/`VerifyOpcode`) — A4-strong, ~64% hit-rate (`PLANTED_BUG_FEASIBILITY.md`)
- Same constraint-polynomial lesson applies (Route 2 proved witgen-only / surgical poly insufficient)
- Seam B requires its own `.zir` edit + regen — not started; documented only

IsRead track continues until step 6 verdict.

---

## Done definition

**Working holed binary** = step 6 mutated-V0 pass: one `(0,1,0)` config **accepts** on bench-isread, **rejects** on patched.

Step 7 (15-entry bracket) = statistical confirmation.

---

## Monitor

```bash
tail -f a4/runs/iv_pos_9/ap/build_spike.log
```

After stage 1 succeeds → stage 2 (`codegen`) → `control-regen` → `honest-gate`.
