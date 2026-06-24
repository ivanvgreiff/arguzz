# Track-B guest suite (ProG_Report_5 §2.2)

Each guest = `guest_main.rs` (the guest program) + `host_main.rs` (the host: baseline harness
VERBATIM — fingerprint emit, injection hooks, prover, verifier — with only the input ABI and a
lenient multi-commit Receipt Decoder changed). `build_sweep_binary.sh <slug>` copies these into
`workspace/output-trackb/methods/guest/src/main.rs` + `host/src/main.rs`, builds against the clean
worktree, and archives the read-only fingerprinted binary (B1.4).

| slug | targets | I/O ABI (host args → guest reads) | notes |
|---|---|---|---|
| `g0_baseline` | the D2.H anchor (u32 arith, 2× div, branch/mux) | `--in0/--in1/--in2/--in3/--in4` (×2) | built + verified in B1 |
| `g1_ecall_control` | `inst_control` + `pre_ecall`/`post_ecall` (A4's strongest) | `--ctrl --gseed --rounds` + 24 derived stage values; guest does many `env::read`/`env::commit` + branches + early exit | ECALL/control-dense |
| `g2_mem_stress` | memory-perm/CGC, load/store, `prev_word`/`prev_cycle` | `--gseed --mask --rounds` | internal array; data-dependent addressing + write-after-read |
| `g3_accelerator` | `core_sha` (SHA accel — empty on baseline) + `inst_div` blind-spot | `--gseed --modulus --rounds` | ⚠ **needs the `sha2` accel patch** (else SHA runs in software, no `core_sha`). B1.4 must add the dep + confirm `core_sha` cycles via A4_INSPECT; fallback = BigInt or the div-rem section alone |

**Naming note:** `--gseed` (not `--seed`) is the GUEST seed — the host already has an injection `--seed`.
**Determinism:** all guests are deterministic + bounded (fixed loop caps) so trace size is stable for
fair cross-variant comparison. The `GUEST_SPECS` input values in `generate_sweep_manifests.py` are
placeholders — B1.4 tunes them so each guest's trace is in the baseline's ~3961-step range.
