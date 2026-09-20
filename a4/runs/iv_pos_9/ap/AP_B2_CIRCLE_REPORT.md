# AP.B2 Circle Report — Composer Post-Mortem for Opus Review

**Date:** 2026-06-23  
**Author:** Composer  
**Purpose:** Stop repeating failed loops. Document exactly what happened, what was real vs illusory progress, and what Opus should decide next.

---

## Executive summary

**AP.B2 is not done.** The IsRead planted bug was **not proven** via `(0,1,0)` corpus + bench/patched bracket.

We spent ~8+ hours across multiple sessions on toolchain and regen infrastructure. That work **did** produce usable Bazel artifacts and both regen snapshots, but the **science gate failed** and several intermediate “PASS” signals were **false positives** caused by incomplete artifact restore, broken orchestration, or a buggy GP1 regex.

**Recommendation for Opus:** Do not re-run full LLVM/Bazel from scratch on this box without fixing the structural issues below. The next attempt needs either (a) a corrected Option B with verified guest↔circuit match, or (b) Seam B / committed-circuit patched baseline + regen-holed bench only, or (c) external host with a single chained script and no background handoffs.

---

## Is “stuck at 1084/1137” normal?

**Short answer:** It looked stuck; it was slow, then **killed**, not hung.

| Observation | Explanation |
|-------------|-------------|
| `[1084 / 1137] Compiling mlir/...AffineOps.cpp` for many minutes | Normal for **cold holed codegen** after `.zir` edit invalidates Bazel cache. LLVM/MLIR rebuild ~25–40 min on this WSL box. |
| PID 897150 gone, log frozen at 1084 | **Abnormal — orchestration failure.** Cursor shell background job hit 600s tool timeout; parent bash died; Bazel child may have continued briefly then orphaned. |
| User sees “not moving at 1084” for hours | Because **no one verified the process** after the handoff, and a **retry was not launched** until the user asked again. |
| Second holed-regen run | Completed in **~5 min** (53 actions) — cache warm, only codegen step reran. |

**1084/1137 was not a deadlock.** It was ~95% through a legitimate long compile that got **interrupted by agent timeout**, then misreported as “running” or forgotten.

---

## Circle 1: Background jobs that never ran

**Pattern:** `spawn /bin/bash ENOENT` in ~50ms.

**Affected launches:**
- `control-regen` (terminal 549656, 2026-06-22 18:49)
- `holed-regen` (terminal 563296, 2026-06-23 01:39)

**Root cause:** Shell cwd `/mnt/c/Users/ivan/.../\\root\\arguzz` — Windows path, bash not found.

**Agent behavior:** Reported “started in background” without `ps` verification.

**User impact:** Hours of perceived progress; zero work done.

**Fix (not yet institutionalized):** Always launch from `/root/arguzz`, verify PID + log growth within 60s, chain steps in one foreground script.

---

## Circle 2: Conda / Zig toolchain rabbit holes (~3–4 hours)

| Attempt | Time | Result |
|---------|------|--------|
| `rules_conda` flexible-solve | ~30–34 min × multiple | Stuck/failed |
| `bootstrap_linux_amd64` (Zig) | Failed at 64/594 | libunwind strict-deps |
| Native host + conda-prune + `--spawn_strategy=local` | ~26 min × 2 | **SUCCESS** — one-time |

**Real artifact:** `zirgen/bazel-bin/zirgen/Main/gen_zirgen`, codegen OUTS cached.

**Circle:** Kept restarting “step 0” instead of recognizing step 0 was done and protecting the cache.

---

## Circle 3: control-regen run 2 — 37 min then bootstrap cwd crash

- Bazel: 1061 actions, ~37 min — **succeeded**
- Bootstrap copy: failed (`Could not open source: bazel-bin/...`) — wrong cwd
- **Fix applied:** `install_codegen_artifacts()` direct copy from `$ZIRGEN/bazel-bin/...`
- **Run 3:** ~4s Bazel + snapshot — **succeeded**

**False end:** Run 3 log also shows `stashed: unbound variable` trap noise (fixed later); snapshot still written.

---

## Circle 4: honest-gate PASS — later proven false positive

**2026-06-22 ~21:39:** `honest_gate.log` → `patched_honest_verifies: true`, `HONEST GATE PASS`.

**2026-06-23 after full pipeline:** Same control snapshot + full `restore_snapshot` → **patched honest verify FAILS** (`verify segment` panic, Prover error ~15s).

**Why the first PASS was wrong:**

`build_ap_binaries.sh` `restore_snapshot` was **incomplete** — missing:
- `types.h.inc`, `types.cuh.inc`
- `defs.cpp.inc`, `defs.cu.inc`
- `layout.cu.inc`, `layout.cuh.inc`, `eval_check.cuh`

First honest-gate build restored partial control snapshot into a workspace that still had **mixed/stale** kernel files from prior holed/surgical state. That accidental mix **happened to verify** the guest.

After fixing restore lists (correct behavior), df6fb9d **control regen alone does not verify** the committed guest image (`--in1 5 --in4 10`).

**Implication:** Option B’s hard gate was **not actually satisfied**. The guest/methods in `workspace/output` were built for the **committed** circuit (`28e53771` era), not df6fb9d regenerated control.

---

## Circle 5: holed-regen — timeout kill at 1084, then redo

1. First holed-regen: `.zir` stash pop OK → Bazel 968→1242 actions (cache invalidation)
2. Agent 600s timeout → job backgrounded → parent died ~1084/1137
3. User asked “still running?” → reported nothing running
4. Second holed-regen: 53 actions, **DONE** → `regen-snapshots/holed-df6fb9dda1c2/`

**Also found:** `install_codegen_artifacts()` omitted `types.h.inc` / `types.cuh.inc` → first `build --from-regen` **failed compile** (`MemoryReadNoIsReadLayout` undeclared). Fixed in scripts; holed-regen re-run; build succeeded.

---

## Circle 6: Rebuild loop without fixing the real gate

| Step | Time | Result |
|------|------|--------|
| `build --from-regen` (1st) | ~17 min | FAIL — missing types.h.inc |
| Fix scripts + holed-regen refresh | ~10s Bazel | OK |
| `build --from-regen` (2nd) | ~19 min | Both binaries built |
| `ap_b1_verify.py` | ~2 min | **FAIL** |
| `ap_b2_replay.py --bracket-only` | ~9.5 min | **FAIL** 0/15 bench accepts |
| Rebuild patched / honest-gate retry | ~10+ min | Still FAIL |

**Circle:** Kept rebuilding binaries without fixing guest↔circuit mismatch or corpus validity under new circuit.

---

## Circle 7: GP1 false failure — regex matches `NoIsRead`

GP1 uses: `IsRead \(.*ReadReg \(`

Holed `rust_poly_fp_*.cpp` loc strings look like:
```
... MemoryReadNoIsRead ( zirgen/.../mem.zir :98:18) at callsite( ReadReg ...
```

Substring **`NoIsRead ( zirgen`** contains **`IsRead ( zirgen`** → **514 false-positive “IsRead@ReadReg” tags**.

**Actual check:** Holed poly lines at ReadReg go through `MemoryReadNoIsRead`, not `IsRead ( mem.zir:79`. Control snapshot still has real `IsRead@ReadReg` at mem.zir:79.

**GP1 `pass: false` is unreliable** for holed regen until regex excludes `MemoryReadNoIsRead`.

---

## Final artifact state (as of report)

| Artifact | Status |
|----------|--------|
| Bazel cache / gen_zirgen | ✅ Done |
| `regen-snapshots/control-df6fb9dda1c2/` | ✅ Exists |
| `regen-snapshots/holed-df6fb9dda1c2/` | ✅ Exists (includes types.h.inc after fix) |
| `a4/builds/ap/patched/risc0-host` | ✅ Built (`circuit_source: zirgen_control`) — **does not verify guest** |
| `a4/builds/ap/bench-isread/risc0-host` | ✅ Built (`circuit_source: zirgen_holed`) — honest verify **passes** |
| `ap_b1_verify.json` | ❌ FAIL |
| `ap_bracket_table.json` | ❌ GP4/GP5 fail (0 bench accepts / 0 genuine) |

**Nothing is running now** except idle Bazel server (PID 779180, no active build).

**Stale “running” terminals in chat UI:** 805627 (honest-gate, exit 0) and 681660 (control-regen run2, exit 1) — **completed jobs**, UI not updated.

---

## Verification results (authoritative)

From `ap_b1_verify.json`:

```json
"V0_smoke": {
  "patched_honest_verifies": false,
  "bench_isread_honest_verifies": true,
  "mutated_bench_accepts": false,
  "mutated_patched_rejects": true,
  "pass": false
}
```

From bracket (`ap_b2_replay.py --bracket-only`):

```
GP4: bench_accept=0, patched_reject=15/15  → FAIL (need bench_accept>0)
GP5: genuine=0/15                           → FAIL
```

**Interpretation:**
- Holed regen **did** change witgen (`steps_cpp_isread_readreg_loc_tags: 0`, ReadReg → MemoryReadNoIsRead).
- **Mutated witnesses reject on both arms** — corpus `(step, txn_idx)` from committed-circuit POS screen **does not transfer** to df6fb9d regen circuits (or mutation no longer hits the holed site).
- Patched df6fb9d control **cannot serve as baseline** for this guest without rebuilding methods/guest for that circuit.

---

## Script fixes applied this session (keep)

| File | Fix |
|------|-----|
| `a4/scripts/ap_zirgen_regen.sh` | `install_codegen_artifacts` now copies `types.h.inc`, `types.cuh.inc` |
| `a4/scripts/build_ap_binaries.sh` | `restore_snapshot` aligned with full regen path list |

**Still broken:**
| Item | Issue |
|------|-------|
| `ap_b1_verify.py` GP1 regex | False positive on `MemoryReadNoIsRead` |
| Agent orchestration | Background timeout kills, no PID checks |
| Option B assumption | df6fb9d control ≠ committed guest circuit |

---

## Timeline of illusory vs real progress

```
REAL:     [gen_zirgen + codegen ~52min] → [control-regen run3] → [holed-regen run2 ~5min]
ILLUSORY: [honest-gate PASS] — mixed workspace false positive
REAL:     [both binaries built from snapshots]
FAIL:     [patched honest verify] [mutated-V0] [bracket 0/15]
WASTED:   [1084/1137 kill + wait] [ENOENT launches ×2] [conda/zig ×N] [rebuild loops ×3+]
```

---

## What Opus should decide (not Composer unilaterally)

1. **Guest/circuit pairing:** Rebuild `risc0-methods` + guest ELF against df6fb9d control before any honest-gate, **or** abandon Option B and use **committed circuit for patched** + holed regen for bench only.

2. **Corpus refresh:** Re-run POS screen on the **actual** patched host circuit to get `(step, txn_idx)` that hit IsRead@ReadReg under the circuit used in bracket.

3. **GP1 gate:** Fix regex to `(?<![a-zA-Z])IsRead \(` or exclude `MemoryReadNoIsRead` before trusting pass/fail.

4. **Orchestration:** Single entrypoint `a4/scripts/ap_b2_finish.sh` — foreground only, exit on first failure, no background.

5. **Seam B fallback:** If IsRead hole cannot produce bench_accepts after corpus refresh, pivot per `PLANTED_BUG_FEASIBILITY.md`.

---

## Circles to avoid repeating

1. ❌ Launch long jobs in background without PID/log verification  
2. ❌ Re-run stage 0 Bazel after cache is warm  
3. ❌ Trust honest-gate without full snapshot restore list  
4. ❌ Rebuild cargo N times without fixing guest↔circuit mismatch  
5. ❌ Treat GP1 poly tag count as ground truth without regex audit  
6. ❌ Tell user “5–15 min remaining” when holed `.zir` invalidates LLVM cache (~30–40 min)  
7. ❌ Leave user to discover idle state after hours  

---

## Logs and snapshots (for Opus verification)

| Path | Content |
|------|---------|
| `a4/runs/iv_pos_9/ap/holed_regen.log` | First run killed ~1084/1137 |
| `a4/runs/iv_pos_9/ap/holed_regen_run2.log` | Successful holed-regen |
| `a4/runs/iv_pos_9/ap/build_from_regen.log` | Full binary build |
| `a4/runs/iv_pos_9/ap/honest_gate.log` | **Misleading PASS** |
| `a4/runs/iv_pos_9/ap/ap_b1_verify.json` | Final verify FAIL |
| `a4/runs/iv_pos_9/ap/ap_bracket_table.json` | 0/15 bench accepts |
| `a4/builds/ap/regen-snapshots/{control,holed}-df6fb9dda1c2/` | Snapshots on disk |

---

## Verdict

Composer **completed the regen pipeline mechanically** but **did not prove AP.B2**. The project went in circles because of orchestration failures, a false honest-gate, incomplete install/restore lists, and bracketing against a corpus/circuit pairing that was never validated after Option B.

**Stop compiling on this path until Opus picks guest/circuit strategy and corpus refresh.**
