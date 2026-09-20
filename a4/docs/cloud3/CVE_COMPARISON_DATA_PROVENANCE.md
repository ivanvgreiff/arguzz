# CVE Comparison — Data Provenance & Analysis-Correctness Guide

**Purpose (2026-06-27):** one page that says, for the cTS-vs-uniform CVE comparison, **which DB to
pull for which question, which binary it ran on, and which numbers are contaminated** — so the final
analysis never pulls from a wrong or contaminated database. Pairs with the binary registry
(`../../runs/iv_pos_9/a1/BINARY_REGISTRY_AND_NOMENCLATURE.md` §6) and the throttle ops doc
(`POS_THROTTLED_DISPATCH_HANDOFF.md`).

---

## 1. The DB inventory (variant × binary × validity)

| variant | binary | step-domain fix? | DB location | contamination | use it for |
|---|---|---|---|---|---|
| **V6_uniform** | B2 (vuln) | n/a (Arguzz uniform) | LOCAL `a4/runs/iv_pos_9/race/cve_results/*/*V6_uniform*/run.db` | **clean** (Arguzz; binary-invariant) | the **CVE baseline** |
| **V6_cTS (orig)** | B2 (vuln) | **NO** (pre-fix) | LOCAL `cve_results/*/*V6_cTS*/run.db` | clean kinds, but **CONFOUNDED** (arms mis-aimed to 436/441) | the *pre-fix* confounded reference only |
| **V6_cTS (re-run)** | B2 (vuln) | **YES** | POS nodes `flare:/root/rerun_v6_cTS_seed{1234..1239}_n5000.db`, `octorand:` 1237-1239 | **clean & valid** | the **post-fix cTS result** |
| **Hybrid (orig)** | B2 (vuln) | NO | LOCAL `cve_results/*/*Hybrid_cTS*/run.db` | **3-kind contaminated** + confounded | pre-everything reference only |
| **Hybrid (re-run)** | B2 (vuln) | YES | POS `opulous:/root/rerun_hybrid_cTS_seed{1234..1236}`, `polynize:` 1237-1239 | **3-kind contaminated** (still on B2) | isolates *step-domain* effect on Hybrid (vs Hybrid-orig), NOT a clean A4 measure |
| **Hybrid (B3, future)** | **B3 (vuln+handlers, to build)** | YES | TBD | **clean** | the *decontaminated* Hybrid allocation/CVE test |
| **V5_control** | B2 (vuln) | n/a | LOCAL `cve_results/*/*V5_control*/run.db` | **3-kind contaminated**; finds 0 CVE regardless | **do not re-run** (pure A4, 0 Arguzz arms, can't surface the CVE) |

**Binaries:** B2 = `a4/builds/a1_cve/risc0-host` (sha `dbe89d23`, VULNERABLE, **no** 3-kind handlers).
G5 = `a4/builds/a1_cve_patched/risc0-host` (CVE **FIXED** — **NEVER use for finding the CVE**).
B3 = vuln+handlers = **does not exist; must be built** (cherry-pick witgen-only `6556e8d7` onto
`workspace/risc0-a1-vuln`). Always verify `sha256` + `guest_image_id` before trusting any binary.

## 2. The CVE metric (apples-to-apples across variants)
**Count = `verifier_accepted=1` AND `kind='INSTR_WORD_MOD'` AND `step IN (444,449)`** (executor remu/divu),
then **replay-classify** with `cve_replay_oracle.py` (committed output `0`=remu / `9000028`=divu /
`1`=both = CVE; `9000027`=benign). This is Arguzz-surface and **binary-invariant**, so it is valid on B2
for V6_cTS / V6_uniform. (For A4-surface arms `step` is user_cycle 436/441 — a *different* domain; do not
mix the two step sets in one count.)

## 3. Which DB answers which question (the recipe)
1. **Does post-fix cTS beat uniform at the CVE?** → re-run **V6_cTS** (POS `rerun_v6_cTS_*`) vs **V6_uniform**
   (LOCAL `cve_results`). Both B2, Arguzz, valid. Metric §2 over all 6 seeds.
2. **Did the step-domain fix change cTS?** → re-run V6_cTS vs **orig** V6_cTS (LOCAL). (Expect: orig had 0
   @444/449, re-run has the redirected shots.)
3. **Decontaminated Hybrid allocation / does Hybrid surface the CVE better when undistorted?** → **B3** Hybrid
   (future) vs **re-run** Hybrid (B2). Requires the B3 build.
4. **Step-domain effect on Hybrid alone (no rebuild needed):** re-run Hybrid (B2) vs orig Hybrid (B2) — both
   3-kind-contaminated identically, so the contamination cancels and only the step-domain fix differs.

## 4. HARD RULES — never violate (each caused or nearly caused a wrong result)
1. **NEVER quote V5 / Hybrid A4 accept counts from B2 as real** — the 3 kinds `CYCLE_DIFF_COUNT_MOD`,
   `TXN_PREV_CYCLE_MOD`, `TXN_PREV_WORD_MOD` are **silent skips** on B2 (100% accept / 0 failures = no-op).
   V5's "33%" and ~91% of Hybrid's accepts are fake. Exclude these 3 kinds from any A4 accept/coverage claim.
2. **NEVER use G5 / `a1_cve_patched` to measure CVE-finding** — it is the fixed binary (rejects the CVE).
3. **NEVER compare across binaries** without confirming the metric is binary-invariant (Arguzz INSTR_WORD is;
   A4 witgen kinds are not). Build the baseline on the same binary as the new runs.
4. **Read DBs ON the node** (they are WAL) — a copied `.db` without its `-wal` sidecar is malformed; verify
   `muts=5000/5000` (a completed job exits `rc=2` but the DB is complete — judge by row count, not exit code).
5. **Verify binary identity** (`sha256` + `guest_image_id`, registry §2) before trusting any `risc0-host`.
6. **The bandit distortion is quantified:** on B2, Hybrid spends **15.2%** of pulls (V5: 33.4%) on the inert
   3 kinds, which score **100% bandit_success** (silent skip → `d_loc=0` → `d_loc≤2` trivially true) and so
   are over-pulled, starving the CVE arm (0.46% of pulls). Any Hybrid allocation claim from B2 is distorted.

## 5. Status snapshot (fill in at analysis time)
- Re-run (V6_cTS + Hybrid × 6 seeds × N=5000, B2, step-domain fix): completing ~03:00 UTC Jun 28.
- For the headline CVE comparison use questions §3.1 + §3.2 (no rebuild needed).
- B3 build + clean Hybrid run (question §3.3) is **pending user go-ahead** (it's a risc0 rebuild).
