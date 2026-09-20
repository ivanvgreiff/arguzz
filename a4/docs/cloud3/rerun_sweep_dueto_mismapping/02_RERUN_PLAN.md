# Re-run plan — IV.POS.9 Track-B sweep, step-domain-fixed

**Prereq reading:** [01_FINDINGS_AND_IMPACT.md](01_FINDINGS_AND_IMPACT.md) (what's valid / what's confounded)
and the upstream `a4/docs/cloud3/arguzz_step_domain_fix/` docs (the bug + fix). This doc says **what to
re-run, on what, how to gate it, and how to know it worked.** It proposes; per the standing constraint, the
source change is already committed but the **POS re-run is confirmed with the user before launch**.

---

## 1. What changes vs. the last re-run (and what does not)

| component | last (3-kind) re-run | this (step-domain) re-run |
|---|---|---|
| per-guest binary | `28e53771_clean__<guest>/risc0-host` (3-kind-patched, `53c21894`) | **same** (fix is rebuild-free — do **not** rebuild risc0/zirgen) |
| Python harness | bundle `05450d8` (**pre-fix**) | bundle from **HEAD `68d90aa`** (`semantic_arm_universe` + `fuzzer._arguzz_zone_major` + `step_domain_map.py` + driver label fix) |
| dispatch infra | Track-B chain (`chain_dispatcher.sh`, `generate_sweep_manifests.py`) | **same** (see `[[iv-pos9-sweep-dispatch]]`, `[[pos-chain-guard-cd-gotcha]]`) |

**Build the fixed bundle** with the existing Track-B builder, which is already `git archive HEAD a4 …` +
the per-guest binaries:

```
bash a4/runs/iv_pos_9/sweep/build_sweep_bundle.sh          # → bundles/sweep_68d90aa2d8be.tar.gz
```

Before scp'ing it, **verify the fix is actually in the bundle** (the failure mode that produced this whole
mess was a bundle that silently lacked a fix):
- `git status` shows **no uncommitted** `a4/standalone/{semantic_arm_universe,fuzzer,step_domain_map,v6_uniform_driver}.py`
  (else the archive misses them — `build_sweep_bundle.sh` overlays dirty files, but committed-at-HEAD is cleaner);
- after build, `tar -tzf bundles/sweep_68d90aa2d8be.tar.gz | grep step_domain_map.py` is non-empty;
- extract-and-grep: `a4/standalone/semantic_arm_universe.py` contains `arguzz_step_to_zone`.

---

## 2. MANDATORY pre-flight: per-guest validation gate (do NOT skip)

The fix's **N=1000 validation passed only on Track A's CVE guest** (`--ctrl 7 --gseed 12345 --rounds 5`). Our
guests g0/g1/g2/g3 have different instruction mixes and host-ecall patterns, so the step↔user_cycle map and
the per-pull guard must be re-proven **per guest** before committing the full campaign. The fix is built to
fail loud (the map builder raises on a bad host-ecall count; the per-pull Layer-1/2 guard aborts the run on
any zone/pc mismatch) — the gate is what surfaces that *cheaply*, before 36 jobs.

For **each** guest g0, g1, g2, g3 (no prover needed for T1/T2; a tiny prover smoke for the guard):

1. **Build the map + assert self-validation** (`step_domain_map.py` on that guest's `--trace`): contiguous
   executor stream, survivor count ≤ witgen total, phantom gap trailing-only, `to_exec` monotone with
   `to_exec(u) ≥ u`, offset == host-ecall count.
2. **T1 invariant audit** (the day-one test): for every Arguzz arm, the instruction at `to_exec(step)` has a
   mnemonic whose class matches the arm's `zone` *and* `opcode_class`. **Zero violations** required.
   (Reference: the committed `a4/standalone/tests/test_step_domain_fix.py` shows the shape;
   MASTER_PLAN §5 T1.)
3. **Guard smoke** (prover, tiny — e.g. V6_cTS, N≈50, 1 seed, on the guest's binary): assert **zero
   step-domain guard aborts** to completion; spot-check that a `core_div`/arithmetic arm injects on the
   executor step whose `--trace` mnemonic is the divide (the per-guest analogue of the CVE's 444/449).

**Gate rule:** if any guest trips (1)–(3), STOP and flag — that guest's geometry hit an edge case the fix does
not yet cover (e.g. a host-ecall sharing a `user_cycle` with a real instruction; see DETAILS §3.1). Do not
launch the full campaign for a guest that has not passed.

---

## 3. Re-run scope

Match the **existing screening design** so the new Arguzz data is directly comparable to the kept V5 data:
**N=5000, seeds 1234/1235/1236, guests g0/g1/g2/g3** (3 seeds — the Track-B screening design; *not* Track A's
6-seed CVE-race design). 1 job/node/batch on the fast 1959 nodes.

| variant | re-run? | jobs (4 guests × 3 seeds) | rationale |
|---|---|---|---|
| **V6_cTS** | ✅ **yes (must)** | 12 | selection + metrics confounded |
| **Hybrid_cTS** | ✅ **yes (must)** | 12 | Arguzz portion confounds the whole variant |
| **V6_uniform** | ⚠️ **recommended** | 12 | selection sound, but CGC/structural labels wrong (headline metric) |
| **V5_control** | ❌ **no — keep** | 0 (keep 12 from the 3-kind re-run) | A4-only; fix is a provable no-op |
| **total** | | **36** (or 24 without uniform) | |

### Two decisions for the user

- **(D1) V6_uniform — re-run vs recompute.** Its mutation *sequence* is identical with/without the fix
  (round-robin ignores zone), so two correct options exist:
  - **Re-run (recommended):** simplest, fully defensible, all variants land on one fixed bundle+binary, no
    offline-reconstruction risk. Cost: +12 jobs (~2 batches on 6 fast nodes ≈ extra ~5 h wall-clock).
  - **Recompute offline:** keep the uniform DBs, recompute CGC/structural by translating each recorded
    executor `step` → `user_cycle` via the map and rebuilding the context keys. Cheaper, but only valid if the
    DB persists every CGC-context input besides zone/major (must be verified first) — and it is harder to
    audit. **Default: re-run.**
- **(D2) V5_control — keep vs re-run for provenance purity.** Keeping V5 (recommended) saves 12 jobs and is
  provably identical (fix is A4-no-op). The only argument to re-run V5 is a *single-bundle* provenance story
  (all four variants from one campaign). **Default: keep**, with the no-op justification recorded in the
  provenance manifest ([03 §4](03_DATA_HYGIENE_AND_MAPPING.md)).

---

## 4. Dispatch (POS)

Same Track-B machinery as the 3-kind re-run, with the fixed bundle:

1. `build_sweep_bundle.sh` → `bundles/sweep_68d90aa2d8be.tar.gz`; scp to coinbase staging.
2. Key + deploy to the fast 1959 sweep nodes (allocate+reset only the keyless ones; zone stays Track A's).
   Use the **disk-backed staging path, not a big bundle into coinbase tmpfs** — the tmpfs-full incident
   (2026-06-27) showed `/tmp` on coinbase is RAM-backed; stage the bundle under a disk path and only push the
   ~48 KB overlay through tmpfs.
3. Generate the manifest with the fixed scope — example for the recommended 36-job set:
   ```
   python3 a4/runs/iv_pos_9/sweep/generate_sweep_manifests.py --stage screening \
     --guests g0_baseline g1_ecall_control g2_mem_stress g3_accelerator \
     --variants V6_uniform V6_cTS Hybrid_cTS --seeds 1234 1235 1236 \
     --nodes <fast live nodes> --out <staging>/stepfix.chain
   ```
   (drop `V6_uniform` for the 24-job set if D1 → recompute).
4. Run the resume-safe chain (`chain_dispatcher.sh`); the per-job G11 fingerprint guard still asserts the
   binary is the clean 3-kind-patched sweep build before each launch.
5. **Coordinate with Track A:** they are running their N=1000 step-domain validation on the Tier-S nodes
   (flare/octorand/opulous/polynize). Pick a non-overlapping node subset or sequence after they finish — do
   not reset nodes running their jobs.

---

## 5. Post-run verification (before any DB enters the clean dataset)

For **each** new run DB:
- **Guard clean:** zero step-domain aborts logged; run reached N=5000.
- **Behavioral proof (the N1000 landmark, per guest):** the Arguzz `core_div`/arithmetic arms inject on the
  *executor* steps whose `--trace` mnemonics are the divides for that guest (the per-guest analogue of
  444/449), and **never** on the pre-fix wrong steps. This is the end-to-end proof the zone is now correctly
  grouped.
- **Provenance stamped:** the DB is tagged with bundle `68d90aa` + binary fingerprint
  (see [03 §4](03_DATA_HYGIENE_AND_MAPPING.md)) — a DB without the stamp must not be plotted.

Then:
- Re-pull into the **clean dataset dir** (not the quarantined `data/`), regenerate the curves + notebook +
  HTML from the clean dir only, and recompute the cross-variant CGC headline on the **unconfounded** data.
- **Re-state the headline carefully:** the "Arguzz wins CGC" claim must be re-derived — the prior number was
  computed on mislabeled CGC keys (inflated) for *both* uniform and cTS. The fix may move it; report the
  post-fix numbers, do not assume the direction holds.

---

## 6. Completion criteria

- [ ] Fixed bundle built from `68d90aa`, fix presence verified in the tarball.
- [ ] Per-guest gate (map self-validate + T1 zero violations + guard smoke zero aborts) passed for g0/g1/g2/g3.
- [ ] V6_cTS + Hybrid_cTS (+ V6_uniform per D1) re-run to N=5000 × 3 seeds × 4 guests, all guard-clean.
- [ ] V5_control pulled from the 3-kind re-run; behavioral landmark + provenance verified for every kept/new DB.
- [ ] Buggy DBs quarantined; clean dataset assembled; notebook/curves read the clean dir only ([03](03_DATA_HYGIENE_AND_MAPPING.md)).
- [ ] Notebook/HTML regenerated; CGC headline re-derived on unconfounded data; MASTER_REPORT updated; F2
      re-assessed on clean numbers.
