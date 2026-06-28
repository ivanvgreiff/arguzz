# A4-surface scheduler ablation on the bug race — overview & decisions

**Date:** 2026-06-27 · **Author:** Opus (Track A), synthesizing 4 research agents (architecture, V0 history, Arguzz scheduler, harness/POS audit). **Status: PLAN ONLY — no code changed.**

## The goal
Re-run the IV.POS.9 Seam-B VerifyOpcode bug race (same guest, same 10 paired seeds 1234–1243, same N=5000) with **two new variants added to the A4 mutation surface**, so we can ask a clean new question: **holding the A4 surface fixed, does the *scheduler* change whether/how fast the planted bug is found?**

- **V0** — A4 surface, **uniform / no bandit** (the historical IV.POS.7 `uniform` selector).
- **V8** — A4 surface, **Arguzz-style balanced round-robin scheduler** (no bandit, deterministic balancing).

Together with the existing **V5_control** (A4 + cTS bandit) this is a **3-way scheduler ablation on one surface**: `uniform (V0) → round-robin (V8) → learned-bandit (V5)`. The existing V6/Hybrid stay as the cross-*surface* complementarity story.

## The variant model (verified)
A variant = **(mutation SURFACE) × (SCHEDULER)**. Surface and scheduler ARE cleanly decoupled in the code (the A4 arm-universe builders are scheduler-agnostic), so this matrix is well-posed:

| | uniform (no bandit) | round-robin (Arguzz-style) | cTS bandit |
|---|---|---|---|
| **A4 surface** | **V0** (new entry / historical `uniform`) | **V8** (NEW code — build) | **V5_control** ✓ exists |
| **Arguzz surface** | **V6_uniform** ✓ (`ArguzzScheduler`) | — | **V6_cTS** ✓ |
| **Hybrid** | — | — | **Hybrid_cTS** ✓ |

## Correcting the V0 recollection (important)
The lead recalled V0 as "V5 but without the bandit, arms chosen uniformly over the trace." Verified against IV.POS.7 (`a4/runs/iv_pos_7/INTERNAL_V0_V6_ANALYSIS.md:24-30`, `MAB_DIAGNOSTIC_FOR_CHATGPT_PRO.md:177-188`):
- ✅ Right: no bandit; A4 surface; arms drawn uniformly.
- ❌ "V5 minus the bandit" is actually **V1** (`zoned`). **V0 is one step below V1** — it has *neither* the bandit *nor* the zoned/semantic prior.
- ❌ "uniformly over the trace" → V0 is uniform over **arms = `(kind, step-bucket)`**, then a uniform step *within* the bucket. It is **NOT** uniform over kinds and **NOT** uniform over trace positions (size-imbalanced zones ⇒ ~99.9% of mutations land in "core"; zone entropy 1.94 ≪ log₂(11)).
- V0 uses the **geometric** `ArmUniverse (kind,bucket)`; V5 uses the **semantic** `SemanticArmUniverse (kind,zone)`. ⇒ the *historical* V0 differs from V5 in **two** axes (scheduler **and** arm discretization) — see Decision 1.
- The `uniform` selector is implemented and live (`cli.py` choices, `fuzzer.py:_setup_uniform`); "V0" as a *named variant* is not in `variants.py`.

## The headline finding that shapes the plan
The dead-arm contamination (3 A4 kinds no-op on the head-`93bda33b` binary — see `../../runs/iv_pos_9/race/CONTAMINATION_IMPACT_VERIFICATION.md`) is **NOT neutral across schedulers**:
- **V0 / V8** (no reward feedback) are **binary-invariant**: the dead arms take a fixed share of draws whether dead or live, so ITM's rate (and find count) is identical on the contaminated vs fixed binary.
- **V5** (bandit) is **inflated** on the contaminated binary: the dead arms earn ~0 reward → the adaptive budget they vacate flows to ITM → V5's ITM-rate (and find count) is ~10–18% higher than its clean value.

⇒ Comparing contaminated-V5 against V0/V8 **biases the ablation toward the bandit**. A clean ablation needs all three on the **fixed binary** (which also yields the clean V5 number, retiring the contamination footnote). This is **Decision 4** and the most consequential one.

## ROUND-2 corrections & resolved decisions (2026-06-27 — supersede earlier drafts in 01/02)
The lead resolved most decisions and corrected V8 + the arm space. Verified by 3 follow-up agents:

- **V8 has NO arms (lead correct).** "Arguzz's scheduler" = balanced round-robin over the **distinct Arguzz-schedulable instruction types** in the trace — the `ArguzzScheduler` `_counter` over mnemonics, filtered to `INSTR_KINDS ∩ has-valid-injection-kind` (so rare *Arguzz-eligible* instructions are sampled as often as common ones; this is Arguzz's own candidate set, NOT literally every trace mnemonic — verified `v6_driver_v2.py:203-206`), then a uniform step within that instruction. It does **not** touch the A4 arm universe. So **V8 = Arguzz instruction-balanced site → uniform A4 kind valid at that site (option b).** **As built = a cli `--selector` `a4_arguzz_sched`** that wraps the ArguzzScheduler + step-domain map + uniform-valid-kind and returns `(kind, user_cycle)` into the existing `_run_single_mutation` path (reusing A4 execution+recording; DB schema = V5's). *(Earlier drafts said "driver fork"; the cli selector is the refinement — see `05` STATUS.)*
  - **⚠️ Step-domain translation is MANDATORY (correctness, not blocker).** The scheduler picks an **executor `current_step`**; the A4 INSTR_TYPE_MOD config needs a **witgen `user_cycle`**. Omitting it silently mutates the *wrong* instruction or skips. The map already exists + is tested (`step_domain_map.py:to_user`, shipped in `68d90aa`); V8 must call it + assert the instruction class matches. (Details: 01 + `arguzz_step_domain_fix/`.)
- **V0 arm space = the up-to-date `SemanticArmUniverse` (lead correct that it's "more than kind/zone").** `ArmKey` is now a 5-field object `(surface, kind, zone, opcode_class, pre_post)` (since `b844e8e`); for the **A4** surface it collapses to `ArmKey.v5(kind, zone)` (the other two are `"n/a"`). So V0 builds arms via **`SemanticArmUniverse.build(data, a4_kinds)`** (V5's exact call) and draws uniformly over `available_arms` — **NOT** the legacy geometric `(kind,bucket)` `ArmUniverse` (that was the *historical* V0; it differs from V5 in two axes). A new `SemanticUniformArmSelector`.
- **Binary: FIXED, re-run V5 AND Hybrid (lead decided).** Build the fixed Seam-B binary (cherry-pick `6556e8d7`), run **V0 + V5 + V8 + Hybrid × 10 seeds = 40 jobs** on it; **reuse** the existing V6_uniform/V6_cTS (Arguzz-surface ⇒ binary-invariant — never touch the 3 dead kinds; label "head 93bda33b, reused"). Kills the contamination confound AND retires the V5/Hybrid inflation footnote.
- **Git: feature branch off `cloud2`, NOT commit-and-revert** (`cloud2` is shared + pushed + the sweep is actively re-bundling). Full strategy + handoff note: **`04_GIT_ISOLATION_AND_HANDOFF.md`**.
- **DB separation documented:** 3 prior Seam-B runs + predecessors + the collision-free `a3seambfix` naming → **`03_CAMPAIGN_INVENTORY.md`**.

### V8 A4-kind choice — RESOLVED: **option (b)** (uniform over A4 kinds valid at the step)
The lead fixed this by the experimental design (below). V8 must be arm-free AND bandit-free in BOTH its site selection (Arguzz instruction-balanced) AND its kind selection (uniform over valid A4 kinds, mirroring Arguzz's uniform-over-valid-injection-kinds). Fixing kind=ITM (option a) would smuggle in a special-case and break the "no arm semantics" baseline. So **(b)**: instr-balanced site → uniform over the A4 kinds valid at that step. ITM is then ~1/k of picks (still ~tens of finds at N=5000).

### THE EXPERIMENTAL DESIGN — a 2-factor ablation ladder on the A4 surface
The A4 scheduler architecture has two components: **arm semantics** (the `(kind,zone)` SemanticArmUniverse structure) and **bandit scheduling** (cTS reward learning). The trio decomposes their individual contributions:

| variant | arm semantics | bandit | isolates |
|---|---|---|---|
| **V8** | ❌ | ❌ | baseline — Arguzz instruction-balanced, no arm structure, no learning |
| **V0** | ✅ | ❌ | **V8→V0: do ARM SEMANTICS help?** (both no bandit) |
| **V5** | ✅ | ✅ | **V0→V5: does BANDIT SCHEDULING help?** (both arm semantics) |

V8→V0→V5 adds one component per rung. This is the architectural point of the experiment: attribute the A4 scheduler's bug-finding to *arm semantics* vs *bandit learning* separately. (The Arguzz-surface variants V6_uniform/V6_cTS + Hybrid carry the orthogonal cross-*surface* story, already run.)

## Document set
- `00_OVERVIEW.md` (this) — goal, matrix, V0 correction, **resolved decisions + the open V8-kind sub-decision**.
- `01_VARIANT_DEFINITIONS.md` — V0/V8 definitions (the ROUND-2 block above is authoritative where it differs).
- `02_IMPLEMENTATION_HARNESS_POS.md` — code edits, harness auto-vs-manual, run plan, analysis updates.
- `03_CAMPAIGN_INVENTORY.md` — every prior run + DBs + the collision-free naming for the fixed run.
- `04_GIT_ISOLATION_AND_HANDOFF.md` — feature-branch strategy + the note to the other tracks.
