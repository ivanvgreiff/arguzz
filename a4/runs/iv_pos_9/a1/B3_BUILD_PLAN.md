# B3 build plan — vulnerable + 3-kind A4 handlers (for the clean Hybrid run)

**Goal:** build **B3 = B2 (still vulnerable, `load_rs2` absent) + the 3 missing A4 witgen handlers**
(`TXN_PREV_WORD_MOD`, `TXN_PREV_CYCLE_MOD`, `CYCLE_DIFF_COUNT_MOD`). Needed because B2 silently skips
those 3 kinds (contamination), distorting Hybrid's bandit allocation. B3 lets Hybrid run *uncontaminated*
while keeping the CVE intact. **Not** for V5 (pure A4, can't surface the CVE) and **not** G5
(`a1_cve_patched`, which is CVE-*fixed*). See `BINARY_REGISTRY_AND_NOMENCLATURE.md` §6,
`../../../docs/cloud3/CVE_COMPARISON_DATA_PROVENANCE.md`.

## Isolation guarantees (nothing existing is touched)
- B2 source `workspace/risc0-a1-vuln` @ `088a0753` (branch `a1-vuln-instr`): **untouched** (verified clean).
- B2 binary `a4/builds/a1_cve/risc0-host` (sha `dbe89d23`): **never rebuilt over**.
- B3 source = **NEW isolated worktree** `workspace/risc0-b3-vulnhandlers`, NEW branch `a1-vuln-b3-handlers`,
  created from `088a0753`. Other worktrees (risc0-modified, risc0-clean-28e53771, risc0-seamb) untouched.
- B3 build = **NEW project** `workspace/output-a1vuln-b3` (copy of `output-a1vuln`, repointed). B3 binary →
  `a4/builds/a1_cve_b3_handlers/risc0-host` (new path).

## The surgical port (verified feasible)
- B2's `witgen/mod.rs` dispatches mutation kinds via `match (mutation_type, target_step)` with arms for
  INSTR_TYPE/INSTR_WORD/COMP_OUT/LOAD_VAL/STORE_OUT/PRE_EXEC_REG/MEM_VAL, then `_ => "invalid config"`
  (line 595). The 3 kinds have **no arm** → fallthrough → silent skip.
- Fix = **add 3 arms** copied from `6556e8d7` (the canonical handlers), inserted **before** line 595:
  - `TXN_PREV_WORD_MOD` (6556e8d7 lines 646–702): `txn.prev_word = new_pw`
  - `TXN_PREV_CYCLE_MOD` (703–740): `txn.prev_cycle = new_pc`
  - `CYCLE_DIFF_COUNT_MOD` (901–932): `cycle.diff_count[idx] = new_d`
- **Verified compile-safe:** the mutated fields all exist in B2's fork (`txn.prev_word` is already assigned
  at B2 line 315; `txn.prev_cycle`/`cycle.diff_count` defined in `preflight.rs`). The closures
  `extract_num`/`extract_str` exist (B2 lines 250/237, in scope). **Only** B2-missing dep = the 2 debug
  helpers `a4_dump_post_mut_txn_window`/`a4_dump_post_mut_cycle_window` → **strip the 3 calls** (lines 694,
  733, 915). They are env-gated (`A4_DUMP_POST_MUT`) debug observability, never active in the campaign →
  stripping changes nothing about the mutation or the proof.
- Everything else in the 3 arms copied **verbatim** (the `txn.prev_word=`/`prev_cycle=`/`diff_count[]=`
  mutation + the `<a4_txn_*_mod>` diagnostic prints).

## Build
- Project: copy `workspace/output-a1vuln` → `workspace/output-a1vuln-b3`; repoint `host/Cargo.toml`
  path deps (`risc0-zkvm`, `fuzzer_utils`) from `risc0-a1-vuln` to `risc0-b3-vulnhandlers`.
- Toolchain: **1.88** (from `output-a1vuln/rust-toolchain.toml` — matches B2; source's 1.85 is overridden).
- `cargo build --release` (host + methods). Expect a long compile.

## Verification gates (ALL must pass before B3 is used)
1. `load_rs2` **absent** in B3 source/binary (still vulnerable) — `strings` / grep.
2. 3 handlers **present** — `strings risc0-host | grep -c` = 1 each for the 3 kinds.
3. `guest_image_id` **== B2's** `[2819774008, 269738887, 492358372, 594138501, 3395406058, 845810525,
   2646011585, 829874012]` (same guest, no execution change → divide stays at exec step **444/449**).
   If it differs → STOP, re-locate the divide steps before any run.
4. Record B3 `sha256` (will differ from B2 — that's expected; the binary changed).
5. **CVE intact:** replay the rs2-alias `INSTR_WORD_MOD` @ step 444 → **accepts**, committed output **0**
   (same as B2). Confirms adding handlers didn't perturb the CVE path.
6. New 3 kinds **work:** replay a `TXN_PREV_CYCLE_MOD` → produces a real mutation (failures/reject), **not**
   `invalid config`.

## After B3 is verified
- Deploy B3 to POS (new bundle/overlay), run **Hybrid_cTS × seeds 1234–1239 × N=5000** on B3 (12... no, 6
  jobs), step-domain overlay applied. Compare Hybrid-on-B3 (clean) vs Hybrid-on-B2 (contaminated re-run) and
  vs uniform. Do NOT re-run V6_cTS/uniform (Arguzz, binary-invariant — reuse). Do NOT run V5.

## Build invocation (matches B2)
```
cd workspace/output-a1vuln-b3
A4_LOAD_RS2_PRESENT=0 A4_PLANTED_BUG=none A4_RISC0_HEAD_SHA=98387806fe8348d87e32974468c6f35853356ad5 \
  cargo build --release          # toolchain 1.88 (project rust-toolchain.toml); guest via embed_methods()
```
Output binary: `workspace/output-a1vuln-b3/target/release/risc0-host` → archive to
`a4/builds/a1_cve_b3_handlers/risc0-host`.

## STATUS LOG (update as we go)
- [x] Isolated B3 worktree created @ 088a0753 (branch a1-vuln-b3-handlers); B2 confirmed untouched.
- [x] Port feasibility verified (fields present, deps present, only a4_dump to strip).
- [x] Ported the 3 arms into B3 witgen/mod.rs (877→1000 lines; verbatim minus 3 env-gated debug calls;
      single fallback verified; arms start/end clean).
- [x] Copied + repointed build project `output-a1vuln-b3` (4/4 path deps → risc0-b3-vulnhandlers, 0 left).
- [x] Fixed inherited absolute self-path: B3 worktree `Cargo.toml` `fuzzer_utils` → b3 (was risc0-a1-vuln,
      caused a lockfile package-collision). B3 source now differs from B2 by exactly 2 files: `witgen/mod.rs`
      (handlers) + `Cargo.toml` (fuzzer_utils path, build-wiring only). NOTE: `.cargo/config.toml` sets
      `-Dwarnings` → any warning fails the build.
- [x] `cargo build --release` (1.88) SUCCEEDED in 102m58s (survived a mid-build host REBOOT; resumed from
      cache). rv32im (my port) compiled clean — the only warning (`unused goal`) is pre-existing in
      `byte_poly.rs`, not my arms. Binary: 89.4MB.
- [x] **B3 IDENTITY:** sha256 `a5b13659108b42685f0c2c2ef34ec75084ed81f21f7739dabc94be6316f1f637`;
      guest_image_id `[1269974820,3877409867,2420062130,1103492329,1369779205,1529891756,3991262003,3366159770]`.
- [x] Gates: G1 load_rs2_present=**0** ✅ (vulnerable), G2 planted_bug=**none** ✅, head=98387806 ✅,
      handlers in binary ✅ (TXN_PREV_WORD/CYCLE/CYCLE_DIFF strings present; B2 had 0).
- [x] **G3 guest_id ≠ B2 — RESOLVED BENIGN.** Executor `--trace` diff (B2 vs B3): both 4786 lines; the
      **divide is at the SAME step on B3** (`step 444 RemU "remu a4,a0,a1"`, `step 449 DivU "divu s0,a2,a3"`,
      identical pc). The 172 differing lines are all data-address immediates — the embedded build path
      (`risc0-b3-vulnhandlers`, +8 chars) grew guest rodata +68B, shifting data addresses. Cosmetic layout,
      NOT instruction/control-flow. → CVE trigger intact at 444/449; B3 = semantically "B2 + 3 handlers".
      **Use B3's OWN guest_id for POS pinning** (not B2's).
- [x] Functional proof PASSED: TXN_PREV_CYCLE_MOD on B3 emits `<a4_txn_prev_cycle_mod>` (real mutation
      prev_cycle 20327→7 at a major=4 divide cycle), `invalid config` count = 0. Handler works; contamination fixed.
- [x] Archived B3 → `a4/builds/a1_cve_b3_handlers/` (risc0-host + sha256.txt + fingerprint.json + README).
      Recorded in BINARY_REGISTRY §2 (row + identity block).
- [ ] Deploy + run Hybrid on B3 (use B3's guest_id), starting flare/octorand when they free ~00:50.

## VERDICT: B3 BUILT + VERIFIED ✅ (2026-06-27) — ready for the clean Hybrid run.
- [ ] Record B3 identity in BINARY_REGISTRY §2 + provenance doc.
- [ ] Deploy + run Hybrid on B3.
