# Phase 7d Inc 3b — Verification of B1 fix + B7 Phase γ

**Date**: 2026-06-11  
**Owner**: Composer  
**Inputs**: `PHASE_7D_INC3_FINDINGS.md`, `PHASE_7D_INC3B_WORK.md`

## Verdict

| Gate | Result |
|------|--------|
| **B1 (post Option B)** | **PASS — 1000/1000** (0 failures, 200 samples × 5 variants) |
| **B7 Phase γ outcome** | flare-pair **0** diffs / octo-pair **1** `mutation_rewards` diff → **octorand has intra-node nondeterminism**; flare is intra-node deterministic |
| **Recommended Phase δ direction** | Chase host/witgen races or CPU microcode-sensitive paths on **octorand** (microcode differs flare `0xa10113e` vs octorand `0xa101116`); re-run verbose capture after host emits `<a4_touch_verbose>` |

---

## A — B1 verifier results

### A.1 Sanity (local, patched host `c2e77443…`)

| Check | Result |
|-------|--------|
| `sanity_V1.json` (`per-kind 10`) | **PASS** — 0 failures |

### A.2 Full strict verifier (POS, 5 parallel shards)

Dispatched via `run_inc3b_b1_verify_pos.sh` on **debian-trixie** with patched-host bundle.

| Variant | Node | Failures | Samples | Verdict |
|---------|------|----------|---------|---------|
| V1 | flare | 0 | 200 | PASS |
| V2 | octorand | 0 | 200 | PASS |
| V3 | opulous | 0 | 200 | PASS |
| V4 | meld | 0 | 200 | PASS |
| V5 | idex | 0 | 200 | PASS |
| **Total** | | **0** | **1000** | **PASS** |

Artifacts: `a4/audits/audit_output/inc3b/B1_V{1..5}.json`

### A.3 Smoke ensemble (pre-fix vs post-fix host)

| Field | Value |
|-------|-------|
| Hosts | pre `6873e588…` / post `c2e77443…` |
| Seed / N | 12345 / 100 |
| `mutations_diff` | **0** |
| Verdict | **PASS** |

**Note**: Ran on WSL (slow path) before POS dispatch was stabilized. Reward-field gate is satisfied; a POS re-run is optional for symmetry (~5 min on one node).

---

## B — B7 Phase γ results

### B.2 Same-node paired runs (zoned, seed=999, n=50, verbose env on)

Successful runs (debian-trixie, pre-fix host `6873e588…`):

| Pair | DB A | DB B | `mutation_rewards_diff` | Pass |
|------|------|------|---------------------------|------|
| flare (flareA vs flareB) | `…21-04-55…/flareA.db` | `…21-10-57…/flareB.db` | **0** | PASS |
| octorand (octoA vs octoB) | `…20-19-52…/octoA.db` | `…22-14-31…/octoB.db` | **1** | FAIL |

**Intra-pair diff counts (V1, audit pass criterion = mutations + bandit + rewards):**

- Same-node intra-flare diff: **0**
- Same-node intra-octorand diff: **1** (`mutation_id=25`: `delta_T` 1 vs 0 between octoA/octoB)

**Cross-node (flareA vs octoA):** same single-bit at `mutation_id=25` (`delta_T` 0 flare / 1 octorand).

Interpretation per work-order table: **octorand exhibits intra-node nondeterminism**; flare does not.

### B.3 Cross-node verbose touch (V1 mut 25)

`A4_COVERAGE_TOUCH_VERBOSE=1` was set on all intra runs (`run_campaign_pos.sh` lines 244–247). Pre-fix host bundle **did not emit** `<a4_touch_verbose>` tags in campaign stdout/logs (0 matches in 47 KB logs).

| Item | Result |
|------|--------|
| `(loc, major, minor)` extra bit | **Could not isolate** — verbose tag absent from host output |
| Parser output | `B7_cross_node_verbose.json` — empty context sets |

### B.4 Fingerprints (flare vs octorand)

| Check | Match? |
|-------|--------|
| `lib_shas.txt` (libstdc++, libc, libm, host) | **Yes** — identical |
| `host_bin` sha256 | **Yes** — `6873e588…` |
| `env.txt` | SSH client IP/port only (expected) |
| `cpuinfo.txt` | **Differs**: microcode `0xa10113e` (flare) vs `0xa101116` (octorand); cpu MHz snapshot; `amd_lbr_pmc_freeze` flag present on octorand only |

Artifacts: `a4/audits/audit_output/inc3b/fingerprint/{flare,octorand}/`

---

## C — Open items for Opus

1. **Verbose touch plumbing**: Confirm whether pre-fix host `6873e588…` supports `<a4_touch_verbose>` in C++ witgen; if not, rebuild with verbose hook for Phase δ bit isolation.
2. **B7 mutation index**: Inc 3 original divergence was `mutation_id=35`; γ intra runs show `mutation_id=25` — same ±1 `delta_T` pattern but different index (expected if octoA run predates parallel optimization; both are single-bit reward diffs).
3. **Octorand microcode**: γ fingerprints show different active microcode revision — candidate for Phase δ env/CPU investigation alongside witgen race audit.

---

## D — Operational notes (for future runs)

- **POS compute**: ~3 sec/mut on test nodes; **setup** (allocate + reset + bundle copy) adds 10–15 min per dispatch.
- **Use `debian-trixie`** — `debian-bullseye` returns 0 inspection cycles with both host builds.
- **B7 bundle**: use pre-fix host (`a4_campaign_inc3b_b7.tar.gz`); patched host is for B1 verify only.
- **Calendar limit**: parallel B7 dispatches hit “Maximum number of future entries is 2” — serialize or free allocations before relaunch.
- **Smoke ensemble belongs on POS**, not WSL/coinbase (~5 min vs ~1 h).

---

## Artifact index

```
a4/audits/audit_output/inc3b/
  sanity/sanity_V1.json
  B1_V{1..5}.json
  smoke_ensemble.json
  B7_intra_flare.json
  B7_intra_octorand.json
  B7_cross_node_verbose.json
  b7_smoke/*.db
  b7_flareA.stdout, b7_octoA.stdout, b7_octoB.stdout
  fingerprint/flare/{env,cpuinfo,uname,meminfo,lib_shas,numa}.txt
  fingerprint/octorand/{env,cpuinfo,uname,meminfo,lib_shas,numa}.txt
```
