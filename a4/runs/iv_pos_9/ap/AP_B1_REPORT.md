# AP.B1 Report — Build `bench-isread` + fingerprint + V0 source gate

**Date:** 2026-06-22  
**Spec:** `a4/docs/cloud3/IV_POS_9_AP_PLANTED_ISREAD_SPEC.md` §5/AP.B1  
**Kickoff:** `a4/docs/cloud3/composer/IV_POS_9_AP_BATCH1_KICKOFF.md`  
**Verification artifact:** `a4/runs/iv_pos_9/ap/ap_b1_verify.json`  
**Status:** **GP1 ✅ · GP2 ✅ · V0 smoke ✅**

---

## 1. Executive summary

AP.B1 delivered two labelled, fingerprinted `risc0-host` binaries on the **current patched tree** (`28e53771`, CVE fixed, `load_rs2_present=1`):

| Build | Path | `planted_bug` | SHA256 |
|-------|------|---------------|--------|
| **patched** (control) | `a4/builds/ap/patched/risc0-host` | `none` | `2a607c68…` |
| **bench-isread** (planted) | `a4/builds/ap/bench-isread/risc0-host` | `isread` / `reg_only` | `efed784a…` |

The planted hole removes **`IsRead` only on the register-read path** by introducing `exec_MemoryReadNoIsRead` and routing `exec_ReadReg` through it. RAM loads, instruction fetch, and paging reads still use `exec_MemoryRead` with `IsRead` intact.

Honest guest runs (`--in1 5 --in4 10`) **verify on both builds**. Automated verification (`a4/scripts/ap_b1_verify.py`) passed all AP.B1 gates.

**What AP.B1 did not do (AP.B2/B3):** no (0,1,0) corpus replay, no PRE_EXEC_REG_MOD accept/reject bracket, no live fuzzing — those are the certainty ladder rungs that prove the *trick* works end-to-end.

---

## 2. Agreement with OCP spec (and one correction)

### 2.1 Agreed

- **Separate binaries per bug** — implemented exactly as specified; outputs live under `a4/builds/ap/{patched,bench-isread}/`.
- **Build on patched tree, not `98387806`** — both binaries built from `workspace/risc0-modified` @ `28e53771`.
- **ReadReg-scoped IsRead removal** — not a global `MemoryRead` weakening.
- **Fingerprint with `planted_bug` + `isread_scope`** — JSON on disk + runtime emit via `A4_INSPECT_FINGERPRINT=1`.
- **V0 smoke** — unmutated proof verifies on both builds.

### 2.2 Pushback: Route 2 wording in the kickoff

The kickoff says Route 2 can “NOP the `IsRead` EQZ pairs whose loc traces through `ReadReg`.” **That loc string does not exist.** In generated `steps.cpp`, all `IsRead` EQZ tags say `at MemoryRead@mem.zir:90`, not `at ReadReg`. `ReadReg` calls `exec_MemoryRead` as a subroutine — there is no per-call-site EQZ.

**Correct surgical Route 2 (what we implemented):**

1. Add `exec_MemoryReadNoIsRead` (copy of `exec_MemoryRead` minus the two `IsRead` EQZ lines).
2. Change **one line** in `exec_ReadReg` to call `exec_MemoryReadNoIsRead` instead of `exec_MemoryRead`.
3. Mirror the same in `steps.cu` + declare in `steps.cuh` for CUDA parity.

Route 1 (zirgen `MemoryReadNoIsRead` + regen) is also prepared in source (`mem.zir`, `inst.zir`) but codegen was not run — the C++ split is equivalent and passes GP1.

---

## 3. What was implemented

### 3.1 Zirgen source (Route 1 documentation / future regen)

| File | Change |
|------|--------|
| `zirgen/zirgen/circuit/rv32im/v2/dsl/mem.zir` | Added `MemoryReadNoIsRead` component (IsForward only, no IsRead). |
| `zirgen/zirgen/circuit/rv32im/v2/dsl/inst.zir` | `ReadReg` now calls `MemoryReadNoIsRead`. |

### 3.2 Generated kernel patch (Route 2 applied)

| File | Change |
|------|--------|
| `workspace/risc0-modified/.../kernels/cxx/steps.cpp` | `exec_MemoryReadNoIsRead` inserted after `exec_MemoryRead`; `exec_ReadReg` redirected. |
| `workspace/risc0-modified/.../kernels/cuda/steps.cu` | Same split for CUDA witgen path. |
| `workspace/risc0-modified/.../kernels/cuda/steps.cuh` | `extern` declaration for `exec_MemoryReadNoIsRead`. |

Managed by **`a4/scripts/ap_isread_patch.py`** (`apply` / `revert` / `status`).

### 3.3 Build + fingerprint infrastructure

| File | Purpose |
|------|---------|
| `a4/scripts/build_ap_binaries.sh` | Builds patched (revert patch) then bench-isread (apply patch); writes binaries + `fingerprint.json`. |
| `a4/scripts/ap_b1_verify.py` | Automated GP1/GP2/V0 checks. |
| `workspace/output/host/src/main.rs` | Emits `<a4_fingerprint>{…}</a4_fingerprint>` when `A4_INSPECT_FINGERPRINT=1`. |

Build-time env vars stamped into the host:

- `A4_PLANTED_BUG` — `none` | `isread`
- `A4_ISREAD_SCOPE` — `reg_only` | empty
- `A4_RISC0_HEAD_SHA`, `A4_LOAD_RS2_PRESENT`, `A4_INSTRUMENTATION_HASH`

### 3.4 Build wall time

Full dual build (patched + bench-isread, each recompiling `rv32im-sys`): **~39 minutes** total on this machine. Expect similar on AP.B2/B3 reruns unless using `--skip-build` with cached binaries.

---

## 4. Gate evidence

### GP1 — source gate ✅

From `ap_b1_verify.json`:

```json
{
  "readreg_uses_memory_read_no_isread": true,
  "exec_memory_read_still_has_isread": true,
  "decode_inst_path_intact": true,
  "isread_loc_strings_in_steps_cpp": 4,
  "zirgen_source_has_memory_read_no_isread": true
}
```

Interpretation:

- **`exec_ReadReg` → `exec_MemoryReadNoIsRead`** — register reads skip IsRead.
- **`exec_MemoryRead` unchanged** — still has both IsRead EQZ (lines 787–790); used by `DecodeInst`, `OpLW`, etc.
- **4 IsRead loc strings remain** in `steps.cpp` — MemoryRead (×2 fields) + MemoryPageIn (×2 fields); none are on the ReadReg path.
- **Zirgen DSL documents the intent** for future full regen.

### GP2 — fingerprint ✅

Both builds carry distinct `host_sha256` and correct flags:

```json
// patched
{ "planted_bug": "none", "isread_scope": "", "load_rs2_present": 1 }

// bench-isread
{ "planted_bug": "isread", "isread_scope": "reg_only", "load_rs2_present": 1 }
```

Runtime emit confirmed: both hosts print `<a4_fingerprint>` with matching `planted_bug` when `A4_INSPECT_FINGERPRINT=1`.

Fingerprints on disk:

- `a4/builds/ap/patched/fingerprint.json`
- `a4/builds/ap/bench-isread/fingerprint.json`

### V0 — smoke proof ✅

Guest args: `--in1 5 --in4 10` (standard POS smoke).

| Build | Honest run verifies? |
|-------|---------------------|
| patched | ✅ |
| bench-isread | ✅ |

Removing IsRead on the register-read path does **not** break honest execution for this guest.

---

## 5. Current tree state (important for AP.B2)

After `build_ap_binaries.sh` completes, the **working tree is left in patched (bench-isread) state** — `ap_isread_patch.py status` → `applied`.

AP.B2 should either:

- Use the pre-built binaries in `a4/builds/ap/` (recommended), or
- Run `python3 a4/scripts/ap_isread_patch.py revert` before building patched-only, or `apply` before building bench-isread.

Do **not** assume `workspace/output/target/release/risc0-host` matches patched without checking patch status.

---

## 6. Handoff to AP.B2

AP.B2 needs:

1. **`bench-isread` binary** — `a4/builds/ap/bench-isread/risc0-host`
2. **`patched` control** — `a4/builds/ap/patched/risc0-host`
3. **Corpus source** — E5 `atoms_n250` (0,1,0) configs, regenerated for race guest trace
4. **V1/V2 bracket** — hand `A4_MUTATION_CONFIG` PRE_EXEC_REG_MOD next_read: bench accepts, patched rejects
5. **V3 genuine-soundness** — witness read ≠ honest execution

AP.B1 does **not** yet prove the IsRead underconstraint trick works for PRE_EXEC_REG_MOD — that is exactly AP.B2’s job.

---

## 7. Risks / notes for reviewers

1. **Rust `steps.rs.inc` mirror** — not patched; witgen uses C++/CUDA kernels. If a future build path switches to Rust step execution, the patch must extend there too.
2. **Full zirgen regen not run** — DSL and generated C++ could drift; regen from `MemoryReadNoIsRead` should be scheduled before thesis freeze.
3. **Build cost** — each patch toggle rebuilds `rv32im-sys` (~10+ min). AP.B2/B3 should pin binaries, not rebuild per config.
4. **Optional Seam B** — not needed before AP.B2; revisit only if V2/V4 hit-rate is too low or V3 shows all no-ops.

---

## 8. Commands to reproduce

```bash
# Build both binaries (~40 min)
bash a4/scripts/build_ap_binaries.sh

# Verify GP1/GP2/V0 (~1–2 min per host smoke)
python3 a4/scripts/ap_b1_verify.py

# Check patch state
python3 a4/scripts/ap_isread_patch.py status

# Inspect fingerprint at runtime
A4_INSPECT_FINGERPRINT=1 a4/builds/ap/bench-isread/risc0-host --in1 5 --in4 10
```

---

## 9. Acceptance checklist (AP.B1)

- [x] `bench-isread` builds; honest guest run verifies
- [x] ReadReg `IsRead` removed; RAM + fetch `IsRead` intact (source evidence)
- [x] `patched` re-stamped, `IsRead` present
- [x] Both builds emit `planted_bug` (`isread`/`none`) + `isread_scope=reg_only`

**AP.B1 complete. Ready for AP.B2.**
