# Binary registry & nomenclature — IV.POS.9 CVE track (so we never run a mistaken/contaminated binary)

**Purpose:** one page that says, for every binary and source tree in play, *what it is, whether it carries
the CVE bug, and what must never be done to it.* Written because names like "B2", "G5", "AP", "Seam-B" are
easy to confuse and a wrong binary silently invalidates the whole experiment.

---

## 1. Plain-language glossary (read this first)

- **The CVE bug** = CVE-2025-52484 / risc0 issue **#3181** = **the "read the same register twice on the same
  cycle" underconstraint** in the rv32im divide path.
  - **Vulnerable behavior:** when an instruction's two source registers are the *same* (`rs1 == rs2`), the
    executor issues **two** register reads → two memory transactions at the same address on the same cycle,
    and the circuit **does not reject** that. Code: `let rs2 = ctx.load_register(decoded.rs2)` (unconditional
    second read), and the circuit's `IsForward` check is `IsCycle(newTxn.cycle − oldTxn.cycle)` which admits a
    zero cycle-gap.
  - **Patched behavior:** when `rs1 == rs2`, the executor reads **once** and reuses the value
    (`fn load_rs2 { if decoded.rs1 == decoded.rs2 { Ok(rs1) } else { load_register(rs2) } }`); the circuit
    adds `ReadSourceRegs`/`is_same_reg` (read once if same) and tightens `IsForward` to
    `IsCycle(newTxn.cycle − 1 − oldTxn.cycle)` so a same-cycle second read becomes `IsCycle(−1)` → invalid.
  - **In one line: the fix is literally "read the register once instead of twice when both operands are the
    same register."** That is exactly what "reading the same register once vs twice" refers to.

- **"B2"** = our **VULNERABLE** binary (the one **WITH** the CVE bug). It is what the CVE race ran against and
  what column ① of the constraint audit was measured on.

- **"G5"** = our **PATCHED** binary (the one **WITHOUT** the CVE bug). Built now to measure column ②. Same
  guest, same instrumentation, same injection CLI — only the fix differs.

- **"A2 guest"** = the *guest program* both B2 and G5 run: `remu a0,a1` + `divu a2,a3` with source registers
  pinned **one bit apart** so a single-bit `INSTR_WORD_MOD` flip aliases `rs2 := rs1`. (Full source in
  `BINARY_REGISTRY` §3; design rationale in `CVE_RACE_ROUND2_GUEST_DESIGN.md`.)

- **"AP track"** = a **separate** project track (accelerator / planted-benchmark) that plants a **different**
  bug (`isread` — an omitted `IsRead` on register reads, via a `MemoryReadNoIsRead` component). **Not the
  CVE. Not ours for this audit.** Its leftover working-tree edits are the contamination source in §4.

- **"Seam-B"** = yet another, **separate** bug: a planted `VerifyOpcode` **decode** bug that is **A4-findable**
  (the mirror race to this CVE). Different commit, different guest, different race.

---

## 2. Binary registry — which has the bug, which doesn't

| name | path | risc0 commit | `load_rs2` | CVE bug? | guest | role |
|---|---|---|---|---|---|---|
| **B2 (VULNERABLE)** | `a4/builds/a1_cve/risc0-host` | `98387806` (2025-05-21) | **absent (0)** | **YES — has the bug** | A2 | CVE race target; audit column ① |
| **G5 (PATCHED)** | `a4/builds/a1_cve_patched/risc0-host` (sha `8300a8c2…`) | `6556e8d7` (risc0-modified) | **present (1)** | **NO — fixed** | A2 (remu @ step **478**) | audit column ②: **REJECTS the mutation** |
| **B3 (vuln + handlers)** | `a4/builds/a1_cve_b3_handlers/risc0-host` (sha `a5b13659…`) | `088a0753` + cherry-port of `6556e8d7` witgen handlers | **absent (0)** | **YES — has the bug** | A2 (remu @ **444**, divu @ **449** — trace-confirmed) | **clean Hybrid run** (3 A4 kinds work, no silent skip) |
| AP patched-control | `a4/builds/ap/patched/risc0-host` | `6556e8d7` | 1 | no (different track) | AP guest | **OTHER TRACK — do not use** |
| AP isread-bench | `a4/builds/ap/bench-isread/risc0-host` | `6556e8d7` | 1 | **no** — plants `isread` bug instead | AP guest | **OTHER TRACK — do not use** |
| Seam-B verifyopcode | `a4/builds/ap_seamb/bench-verifyopcode/risc0-host` | `93bda33b` | 1 | no — plants `verifyopcode` bug | Seam-B guest | **OTHER BUG — do not use** |
| Seam-B control | `a4/builds/ap_seamb/control/risc0-host` | `93bda33b` | 1 | no | Seam-B guest | **OTHER BUG — do not use** |
| sweep g0–g3 | `a4/builds/sweep/28e53771_*` | `28e53771` | — | no | sweep guests | **screening sweep — do not use** |

**B2 identity to verify before any use** (immutable):
- `sha256 = dbe89d232d607fd3a606bf01dfc7257739ba0de76d7787b459c55945e875c2cb`
- A2 `guest_image_id = [2819774008, 269738887, 492358372, 594138501, 3395406058, 845810525, 2646011585, 829874012]`
- `fingerprint.json: {risc0_head_sha: 98387806…, load_rs2_present: 0, planted_bug: none}`

**G5 identity** (to be recorded post-build): sha256 + the **same** A2 `guest_image_id` as B2 (verified after
build — if it differs, the remu step index must be re-located before running the audit mutation).

**B3 identity** (built + verified 2026-06-27):
- `sha256 = a5b13659108b42685f0c2c2ef34ec75084ed81f21f7739dabc94be6316f1f637`
- `guest_image_id = [1269974820, 3877409867, 2420062130, 1103492329, 1369779205, 1529891756, 3991262003, 3366159770]`
  — **DIFFERS from B2** (the longer embedded build-path `risc0-b3-vulnhandlers` grew guest rodata +68B,
  shifting data-address immediates). **This is benign:** executor `--trace` diff vs B2 shows the divide at the
  **same** steps (remu @444 `remu a4,a0,a1`, divu @449 `divu s0,a2,a3`, identical pc) — only data-address
  immediates differ. CVE trigger intact at 444/449. **Use THIS guest_id for B3's POS pinning, never B2's.**
- `fingerprint: {load_rs2_present: 0, planted_bug: none, risc0_head_sha: 98387806…}` (vulnerable).
- Handlers verified working: `TXN_PREV_CYCLE_MOD` applies a real mutation (prev_cycle 20327→7 at a major=4
  divide cycle), NOT `invalid config`. Build plan + gates: `B3_BUILD_PLAN.md`.

---

## 3. Source trees (where binaries are built from)

| tree | commit | what it is | contains CVE bug? |
|---|---|---|---|
| `workspace/risc0-a1-vuln` | branch `a1-vuln-instr` @ `088a0753` (risc0 base `98387806`) | **B2's source** — forward-ported vulnerable + Arguzz `--inject` infra + A4 touch/fail instrumentation; `load_rs2` removed | **YES** |
| `workspace/risc0-modified` | `6556e8d7` (base `ebd64e43`) | **G5's source** — the patched + instrumented tree (`load_rs2` present, circuit has `ReadSourceRegs`/`is_same_reg`); also the shared base for the AP track | **NO** |
| `zirgen` (working tree) | dirty `M inst.zir, mem.zir` | the zirgen DSL checkout — **locally modified by the AP track** (`MemoryReadNoIsRead`). Newer than B2's era. | — |
| `workspace/output-a1vuln` | — | the **B2 build project** (host+methods); points at `risc0-a1-vuln` | builds B2 |
| `workspace/output-a1patched` | — | the **G5 build project** (host+methods, copied from output-a1vuln); points at `risc0-modified`; toolchain 1.90 (ruint MSRV) | builds G5 |

**Pinned circuit source for reading B2's constraints:** zirgen **`e85a176e`** (2025-03-17) — matches B2's
telemetry line numbers exactly. Read it with `git -C zirgen show e85a176e:zirgen/circuit/rv32im/v2/dsl/<f>.zir`.

---

## 4. Contamination rules (do / never)

1. **NEVER read `/root/arguzz/zirgen`'s working-tree `inst.zir`/`mem.zir` as B2's circuit.** They carry AP's
   uncommitted `MemoryReadNoIsRead` plant (a *different* bug) and are a *newer* revision than B2. For B2
   semantics always use `git -C zirgen show e85a176e:…`. (This trap was hit and caught during column ①.)
2. **NEVER rebuild over B2.** `a4/builds/a1_cve/risc0-host` must keep sha `dbe89d23…`. Do not build into it.
3. **NEVER patch `workspace/risc0-a1-vuln` in place and rebuild `output-a1vuln`** — that would silently turn
   B2's build project into a non-B2 (patched) binary. G5 is built in a **separate** project
   (`output-a1patched`) against `risc0-modified`, leaving the vuln tree byte-untouched.
4. **NEVER use AP / Seam-B / sweep binaries for the CVE audit.** Only B2 (vuln) and G5 (patched), both A2.
5. **Always verify identity before a run:** check `sha256` + `guest_image_id` against §2 before trusting any
   `risc0-host` for the CVE audit.
6. **One guest, both binaries:** the A2 guest source is byte-identical between B2 and G5 (`diff -q` clean).
   The comparison is valid only if the built `guest_image_id` also matches (verified post-build).

---

## 5. RESOLVED BY MEASUREMENT (2026-06-26): the fix IS related

G5 was built (sha `8300a8c2c87eda94a7d4288880022607cd9de8428e1aa6d9e2492aa363d5126c`, remu at `--inject-step
478`, honest output 9000027 verified) and run on the identical mutation. **Result: G5 REJECTS it.**

- B2 (vulnerable) @444: rs2-alias → **accepted**, output 0, Verifier success, 0 constraint_fail (same-session
  re-confirmed).
- G5 (patched) @478: same rs2-alias → **prover error, `verify segment` panic**, 2 `constraint_fail` at the
  remu cycle (major=4,minor=7): `MemoryWrite(mem.zir:99)` resid 17966, `MemoryWrite(mem.zir:100)` resid 15.
- **Control (CVE-specificity):** G5 *accepts* benign non-aliasing mutations at the same step (seed 11 flips
  rd, seed 33 other → 0 fails) and rejects garbage (seed 22 → 4 fails). So the rejection is **specific to the
  rs2-alias (rs1==rs2)**, not a general injection breakage.

**Therefore: the #3181 / load_rs2 fix flips this exact mutation accept→reject.** The detecting constraint is
the remu **writeback `MemoryWrite`** (E+P on B2, E+F on G5) — *not* the register read or `IsCycle(−1)` that
were predicted; measurement corrected the guess, and there is no preflight `ensure` abort (it reaches
witgen+prove, then segment verification fails). Full record: `CVE_CONSTRAINT_AUDIT_PLAN.md` (RESULT HEADLINE)
+ `logs/audit_patched_full.log`. Open micro-question (value-level, not to be guessed): *why* the writeback
specifically — dump the witnessed `decoded.rs2`/read/write values at the remu cycle on both binaries.

---

## 6. 3-KIND A4 CONTAMINATION ON B2 — and why NEITHER binary is right for a clean V5/Hybrid run (2026-06-27)

**B2 lacks the witgen handlers for 3 A4 kinds** (`TXN_PREV_WORD_MOD`, `TXN_PREV_CYCLE_MOD`,
`CYCLE_DIFF_COUNT_MOD`, added in `6556e8d7`). On B2 they hit the `invalid config` fallback → trace
UNCHANGED → honest proof → **verifier ACCEPTS a no-op**, logged as `applied`/`accepted`. Verified:
`strings a4/builds/a1_cve/risc0-host` = **0/0/0** for the 3 kinds (MEM_VAL_MOD/INSTR_TYPE_MOD present);
data (V5 seed1234) = the 3 kinds **100% accept, 0 failures** (556/556 …) vs implemented kinds **0% accept**.
This is the SAME bug as the Track-B sweep (`../sweep/CONTAMINATION_AND_FIX_3KIND.md`), now confirmed on the
CVE B2 binary. **Consequence:** in the original CVE race AND the step-domain re-run, **V5_control + Hybrid_cTS
A4 accepts are FAKE** (V5 real accept rate ≈0; Hybrid ~91% of accepts fake; Hybrid bandit allocation
distorted). **V6_cTS + V6_uniform are VALID** (`INSTR_WORD_MOD` is executor-injection, needs no witgen handler).

**Binary suitability for finding the CVE with working A4 mutations:**
| binary | vulnerable (CVE present)? | 3-kind handlers? | usable for clean V5/Hybrid CVE run? |
|---|---|---|---|
| B2 `a1_cve` | YES | **NO** | ❌ contaminated A4 |
| G5 `a1_cve_patched` | **NO (CVE fixed)** | YES | ❌ **no CVE to find — NEVER use for this** |
| *(needed)* B3 = vuln + handlers | YES | YES | ✅ — **does not exist; must be built** |

⚠️ **NEVER use G5/`a1_cve_patched` to measure CVE-finding** — it is the *fixed* binary (rejects the CVE by
design). The clean V5/Hybrid run needs a **NEW binary**: cherry-pick the **witgen-only** `6556e8d7`
(+345/−2) onto `workspace/risc0-a1-vuln` (@088a0753, base 98387806) — leaving `load_rs2` ABSENT (stays
vulnerable) — and rebuild in a fresh project (do NOT rebuild over B2 or into `output-a1vuln`; per §4 rules).
Caveat: `6556e8d7`'s parent is `28e53771`, not `98387806`, so the cherry-pick may not apply cleanly
(witgen/mod.rs differences) — verify the build's `guest_image_id` and re-confirm CVE-trigger before use.
**This is a risc0 REBUILD → flag & ask the user before doing it.**

**Is the rebuild necessary?** Not for the CVE conclusion. A4 already finds **0** real CVE candidates on B2
(V5: 603 `INSTR_WORD` attempts at the divide, 0 accepts; implemented A4 kinds accept 0%), and the 3
contaminated kinds (cycle/transcript) are orthogonal to the divide path. The V6_cTS-vs-uniform comparison
(valid, Arguzz-only) settles the thesis question. The clean V5/Hybrid run is **completeness-only** (accurate
A4 general coverage + undistorted Hybrid allocation). **In all reports, mark V5/Hybrid A4 accepts on B2 as
contaminated; never quote the fake counts as real.**
