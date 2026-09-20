# DATA PROVENANCE — post-fix CVE comparison (so we never confuse a database)

Human-readable companion to `lib/data_access.py` (the machine-readable registry). Every number in the
notebooks traces to a row here. **NEW** = downloaded into `data/`; **EXISTING** = read-only in `../race/cve_results`.

## The binaries (which guest/circuit each dataset ran on)
| binary | path | load_rs2 | CVE? | 3-kind A4 handlers | guest_image_id |
|---|---|---|---|---|---|
| **B2** | `a4/builds/a1_cve/risc0-host` (sha `dbe89d23`) | absent (0) | **YES (vuln)** | **NO** (silent-skip) | `[2819774008,…]` |
| **B3** | `a4/builds/a1_cve_b3_handlers/risc0-host` (sha `a5b13659`) | absent (0) | **YES (vuln)** | **YES (work)** | `[1269974820,…]` (cosmetic diff; divide still @444/449) |
| ~~G5~~ | `a4/builds/a1_cve_patched/risc0-host` | present | **NO (fixed)** | yes | — | **NEVER use to find the CVE** |

## The datasets
| key | label | origin | binary | seeds | valid for CVE | contamination |
|---|---|---|---|---|---|---|
| `v6_cTS_postfix` | V6_cTS (post-fix) | **NEW** `data/v6_cTS_postfix/` | B2 | 1234–39 | **YES** | none (pure Arguzz) |
| `hybrid_B2_postfix` | Hybrid (post-fix, B2) | **NEW** `data/hybrid_B2_postfix/` | B2 | 1234–39 | **Arguzz-only** | A4 surface FAKE (3-kind silent skip) |
| `hybrid_B3_clean` | Hybrid (clean, B3) | **NEW** `data/hybrid_B3_clean/` | B3 | 1234–39 | **YES** | none (handlers work) |
| `v6_uniform_baseline` | V6_uniform | **EXISTING** read-only | B2 | 1234–39 | **YES** | none (Arguzz uniform) |
| `v5_control` | V5_control (A4) | **EXISTING** read-only | B2 | 1234–39 | NO | A4 FAKE; finds 0 CVE |
| `v6_cTS_prefix` | V6_cTS pre-fix | **EXISTING** read-only | B2 | 1234–39 | CONFOUNDED | step-domain bug (contrast only) |
| `hybrid_prefix` | Hybrid pre-fix | **EXISTING** read-only | B2 | 1234–39 | CONFOUNDED | step-domain + 3-kind (contrast only) |

## The metric (apples-to-apples across all variants)
**CVE candidate** = `verifier_accepted=1 AND kind='INSTR_WORD_MOD' AND step IN (444,449)` (executor remu/divu).
Binary-invariant Arguzz surface → valid on B2 *and* B3, comparable across all variants. Confirm candidates
with the replay-oracle (committed output `0`=remu / `9000028`=divu / `1`=both = CVE; `9000027`=benign).
`lib/cve_metrics.py` computes this; the divide steps 444/449 are trace-confirmed identical on B2 and B3.

## Which dataset answers which question
1. **Does post-fix cTS beat uniform?** → `v6_cTS_postfix` (NEW) vs `v6_uniform_baseline` (EXISTING).
2. **Did the step-domain fix change cTS?** → `v6_cTS_postfix` (NEW) vs `v6_cTS_prefix` (EXISTING contrast).
3. **Does decontaminating A4 change Hybrid?** → `hybrid_B3_clean` (NEW) vs `hybrid_B2_postfix` (NEW).
4. **Hybrid vs uniform (clean)** → `hybrid_B3_clean` (NEW) vs `v6_uniform_baseline` (EXISTING).
5. **A4 can't find it** → `v5_control` (EXISTING): expect 0 candidates.

## Current finding (candidate-level, pre-replay; from the 04:09–08:44 runs)
V6_cTS = **9**, V6_uniform = **9** (tied); Hybrid_B2 = **3**; Hybrid_B3 = TBD (finishing); V5 = **0**.
→ post-fix, cTS ties uniform; Hybrid trails; A4 none. Replay-oracle pending to convert candidates→confirmed.

## Notebook rule
Import `from lib.data_access import SOURCES, BY_KEY, open_ro, cve_candidates`. Use `s.db_paths()` for
seed→path. NEW data comes from `data/`; EXISTING comes read-only from `cve_results`. Never write any DB.
