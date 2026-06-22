# Composer Kickoff — AP.B1: Build `bench-isread` (remove ReadReg `IsRead`) + fingerprint + source gate

**Parent spec:** [`../IV_POS_9_AP_PLANTED_ISREAD_SPEC.md`](../IV_POS_9_AP_PLANTED_ISREAD_SPEC.md) §5/AP.B1 · **Status:** READY · **Gates:** GP1, GP2 · **Reviewer:** Opus.

## 0. Objective
Produce **`bench-isread`**: the current patched instrumented `risc0-host` with the `IsRead` register-read-consistency constraint **removed on the register-read path only** (`ReadReg`), leaving RAM-load and instruction-fetch `IsRead` intact. Also re-stamp the unmodified `patched` build as the control. This is the binary on which A4's `PRE_EXEC_REG_MOD next_read` will become an accepted-invalid soundness bug (proven in AP.B2/B3). **Do not touch the CVE / vulnerable commit — build on the current tree.**

## 1. Context
- **Bug = remove `IsRead`** (`zirgen/zirgen/circuit/rv32im/v2/dsl/mem.zir:77-81`: `IsRead(io){ io.oldTxn.dataLow=io.newTxn.dataLow; io.oldTxn.dataHigh=io.newTxn.dataHigh; }`), compiled to two `EQZ` in `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp` (loc `IsRead@mem.zir:79` / `:80` `at MemoryRead@mem.zir:90`).
- **Scope to register reads:** `IsRead` is reached via `MemoryRead`, used by `ReadReg` (`inst.zir:36`, register reads — the target), RAM `OpLW`/store-data, and instruction fetch (`DecodeInst@inst.zir:29`). Remove it **only for the `ReadReg` path**. The compiled loc strings distinguish call sites (`…IsRead@79 at MemoryRead@90 at ReadReg…` vs `…at OpLW…` vs `…at DecodeInst…`).
- Build on the **current patched tree** (`workspace/risc0-modified` @ `28e53771`; `load_rs2` present → CVE fixed). No back-port.

## 2. Deliverables
1. **`bench-isread`** `risc0-host` (ReadReg `IsRead` removed) — clearly named/separated from `patched` and any CVE build.
2. **`patched`** re-stamped (unchanged circuit; `IsRead` present) — the control.
3. **Fingerprint** (extend the L14/G10 mechanism from A1.B2): add `planted_bug: none|isread` and `isread_scope: reg_only`. `bench-isread`→`isread`, `patched`→`none`.
4. **GP1 source gate** + **smoke proof** evidence.

## 3. Steps
1. **Pick the removal route:**
   - **Route 1 (preferred if zirgen runs):** add `MemoryReadNoIsRead` to `mem.zir` (copy of `MemoryRead`@90 minus the `IsRead(io)` call), point `ReadReg`@`inst.zir:36` at it, regenerate `steps.cpp`/`layout`/`poly_ext` (the #3181-style codegen).
   - **Route 2 (surgical, no zirgen):** in `steps.cpp`, locate the `IsRead` `EQZ` pairs whose loc traces through `ReadReg` (not `OpLW`/`DecodeInst`) and replace each with a no-op (or `EQZ(0,...)`). Leave RAM/fetch `IsRead` EQZ untouched.
   - Use whichever **builds + passes GP1**. Document the route.
2. **Build** `bench-isread` (`cargo build --release` in `workspace/output`; guest embeds via `methods/build.rs`).
3. **GP1 source gate:** confirm ReadReg-path `IsRead` EQZ absent in `bench-isread`, present in `patched`; confirm RAM-load + fetch `IsRead` present in **both**. Record grep/objdump evidence.
4. **Smoke proof:** an **unmutated** honest guest run **verifies** on both `bench-isread` and `patched` (removing IsRead must not break honest execution).
5. **Fingerprint (GP2):** extend the build fingerprint with `planted_bug`/`isread_scope`; stamp both builds; emit via the `A4_INSPECT_FINGERPRINT` path (reuse A1.B2's mechanism).

## 4. Acceptance (GP1, GP2)
- [ ] `bench-isread` builds; honest guest run verifies.
- [ ] ReadReg `IsRead` removed; RAM + fetch `IsRead` intact (source/objdump evidence).
- [ ] `patched` re-stamped, `IsRead` present.
- [ ] Both builds emit `planted_bug` (`isread`/`none`) + `isread_scope=reg_only`.

## 5. Guardrails
- **Scope discipline:** removing IsRead globally (RAM + fetch too) is WRONG — it over-broadens the hole and muddies the bug. Register-read path only.
- **Do not** modify the CVE / build on `98387806` here — `bench-isread` is the patched tree.
- **Do not** weaken any other constraint — only `IsRead` on `ReadReg`. (AP.B3's negative controls will check this.)
- Keep `bench-isread`, `patched`, and (later) `bench-cve` in clearly separated, labelled locations.

## 6. Definition of done
`bench-isread` exists, is provably scoped (GP1), honest runs verify, and both builds carry the `planted_bug` fingerprint (GP2). Hand both binaries to AP.B2.
