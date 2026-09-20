# `a4/builds/` — compiled `risc0-host` binaries

> ## ⚠️ DANGER: some binaries here are DELIBERATELY UNSOUND — they ACCEPT invalid proofs.
> Never treat a binary in this tree as a normal RISC Zero prover without checking its fingerprint.
> **A binary is safe for general use only if `planted_bug == none` AND `load_rs2_present == 1`.**
> The CVE builds report `planted_bug: none` — their vulnerability is flagged by `load_rs2_present: 0`.

The binaries themselves are **git-ignored** (~86–99 MB each, over GitHub's 100 MB limit) and live on local
disk only. Each directory keeps a **tracked `fingerprint.json`** (+ `sha256.txt` / `README.txt`) that
identifies and verifies it. Rebuild via the scripts in [`../scripts/`](../scripts/) (see the root
[README](../../README.md) §3).

## Verify any binary before using it

```bash
# Print the binary's self-reported build fingerprint:
python -m a4.pos.fingerprint_guard a4/builds/<dir>/risc0-host --emit-json

# Or assert it matches an expected profile (exit 0 = ok, non-zero = ABORT):
python -m a4.pos.fingerprint_guard a4/builds/<dir>/risc0-host --profile sweep
#   profiles: sweep (sound), race (CVE-vulnerable), verifyopcode (Seam-B holed), isread (Seam-A holed)
```

The fingerprint is baked at compile time (`option_env!` in the build harness `host/src/main.rs`) and emitted
at runtime under `A4_INSPECT_FINGERPRINT=1`, so it cannot drift from the binary.

## Master table

| Binary | Soundness | `planted_bug` | `load_rs2` | handlers | source @ commit | sha256 |
|---|---|---|---|---|---|---|
| `sweep/28e53771_clean__g0_baseline` | ✅ SOUND | none | 1 | 15 | risc0-clean-28e53771 @ `53c21894` | `f70f8c6a…` |
| `sweep/…__g1_ecall_control` | ✅ SOUND | none | 1 | 15 | `53c21894` | `527d71f5…` |
| `sweep/…__g2_mem_stress` | ✅ SOUND | none | 1 | 15 | `53c21894` | `58d74710…` |
| `sweep/…__g3_accelerator` | ✅ SOUND | none | 1 | 15 | `53c21894` | `5653b24d…` |
| `a1_cve_patched` (G5) | ✅ SOUND (CVE fixed) | none | 1 | 15 | risc0-modified @ `6556e8d7` | `8300a8c2…` |
| `ap/patched` | ✅ SOUND | none | 1 | 15 | risc0-modified @ `6556e8d7` | `e4e9c480…` |
| `ap_seamb/control` | ✅ SOUND ⚠️7-handler | none | 1 | 7 | risc0-seamb @ `93bda33b` | `4e0f841c…` |
| `ap_seamb_fix/control` | ✅ SOUND | none | 1 | 10 | `f3c659a8` (=93bda33b + 6556e8d7) | `7b968b21…` |
| `ap_seamb/bench-verifyopcode` | ⛔ PLANTED (decode hole) ⚠️7-handler | **verifyopcode** | 1 | 7 | risc0-seamb @ `93bda33b` | `53ee6663…` |
| `ap_seamb_fix/bench-verifyopcode` | ⛔ PLANTED (decode hole) | **verifyopcode** | 1 | 10 | `f3c659a8` | `6935ac1d…` |
| `ap/bench-isread` | ⛔ PLANTED (dead Seam-A) | **isread** | 1 | 15 | risc0-modified @ `6556e8d7` + isread patch | `677c54e9…` |
| `a1_cve` (B2) | ⛔ CVE-VULNERABLE | none ⚠️ | **0** | 7 | risc0-a1-vuln @ `088a0753` (base 98387806) | `dbe89d23…` |
| `a1_cve_b3_handlers` (B3) | ⛔ CVE-VULNERABLE | none ⚠️ | **0** | 10 | risc0-b3-vulnhandlers @ `088a0753` | `a5b13659…` |

## What each is for

- **`sweep/*`** — clean prover, one per guest program (g0–g3). Used for the coverage sweep. Safe.
- **`ap_seamb_fix/{control,bench-verifyopcode}`** — the **Seam-B** planted-decode-hole pair used by the final
  A3 bug race. `control` is sound; `bench-verifyopcode` accepts instruction-type substitutions.
- **`a1_cve` / `a1_cve_patched` / `a1_cve_b3_handlers`** — the **CVE-2025-52484** (rs1==rs2 double-read) race:
  vulnerable / patched / vulnerable-with-A4-handlers-for-Hybrid.
- **`ap_seamb/*`** — the *original* Seam-B pair, **superseded** by `ap_seamb_fix/*` (see handler note).
- **`ap/{patched,bench-isread}`** — the **dead Seam-A** (IsRead) track; the hole is caught by the global
  memory argument, so it was abandoned. Kept for the record.

## The handler-tier caveat (⚠️7-handler)

The A4 mutation handlers are compiled in, and older binaries have fewer of them:
- **7-handler** (`a1_cve`, `ap_seamb/*`) — **missing** `TXN_PREV_WORD_MOD`, `TXN_PREV_CYCLE_MOD`,
  `CYCLE_DIFF_COUNT_MOD`. Running the current fuzzer against these makes those 3 kinds **silently no-op**
  (recorded as false ACCEPTs). This is the "3-kind contamination." Use the **10-handler** replacements
  (`a1_cve_b3_handlers`, `ap_seamb_fix/*`) instead.
- **10-handler** — full set the current fuzzer emits (`a1_cve_b3_handlers`, `ap_seamb_fix/*`).
- **15-handler** — 10 + 5 dead W-17/W-18 kinds the fuzzer no longer emits (`sweep/*`, `a1_cve_patched`, `ap/*`).

`fingerprint_guard.py` now also checks the handler set (`--require-handlers …`), so a stale binary aborts
instead of silently no-op'ing.
