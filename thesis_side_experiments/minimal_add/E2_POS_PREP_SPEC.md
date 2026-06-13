# E2-PREP — stand up + smoke-validate the thesis POS execution path

> **Goal:** before running the full E2/E3 matrices (>10 proofs ⇒ POS), build and
> **prove** a minimal POS execution path for our two run types — Arguzz `--inject`
> and A4 `A4_MUTATION_CONFIG` — using the **frozen** host, and cross-validate that POS
> reproduces the WSL E1 results byte/layer-identically. Do NOT run the full E2 yet.

---

## 0. Non-negotiable banner

- **FROZEN HOST — do NOT rebuild.** Ship the E0-frozen binary
  `frozen_host/thesis-minimal-host.e0frozen`
  (sha256 `5337f9448d7946c5785f1506b0fbfbfa07d32d6542e60c9cc158a22ce0611d23`).
  Assert the sha before bundling (`host_guard.py`). Never run `./build.sh` for E2/E3.
- **Flag contract (must match E1 exactly), from `bias_campaign/run_common.py::DEFAULT_ENV`:**
  `CONSTRAINT_CONTINUE=1`, `A4_COVERAGE_TOUCH=1`, `A4_COVERAGE_TOUCH_VERBOSE=1`,
  `A4_FAMILY_RESIDUE=1`, `A4_GLOBAL_RESIDUE=1`. Export these for **both** run types on-node.
- **Run invocations (replicate exactly):**
  - Arguzz: `host --trace --inject --inject-step <step> --inject-kind <kind> --seed <N>`
    (minimal_add guest takes **no** guest args → `guest_args=[]`).
  - A4: `host` with env `A4_MUTATION_CONFIG=<config.json>` (no guest args).
- **THE AGENT NEVER TOUCHES THE CALENDAR.** Reservation is the user's manual web-UI step
  (see `bias_campaign/POS_NOTES.md` "thesis node reservation"). Composer only dispatches
  with **`--allocation-duration 0`** against the already-reserved, dedicated, fast node,
  **after** its `start_date` has passed.
- **POS image MUST be `debian-trixie`** (the host needs GLIBC 2.39+; bookworm fails — §12.30).

---

## Phase P1 — build + WSL validation (NO POS; composer can do this now)

### P1.1 — forced-value config path (E2 plan step 1)
Extend `bias_campaign/a4_config.py::build_a4_config` with an optional
`forced_value: Optional[int] = None`. When set, **bypass `pick_mutated_value`** and pass
`forced_value` straight into the relevant `create_*_config` (for `INSTR_WORD_MOD_FULL`
the forced value is the exact 32-bit word). Keep the seed path unchanged when `None`.

### P1.2 — bake E2 A4 configs LOCALLY from E0 inspection data
Configs are built locally (they need `InspectionData`); the node only *runs* them.
- Load the E0 trace/inspection (same `InspectionData` E0/run_e1 used; reuse the site card
  `artifacts/e0/site_card.json` for `a4_step` per role).
- For **each E1 constraint-layer run** (exclude the 7 PROVE_ERROR control-flow seeds —
  A4 can't "mirror a crash"), build an A4 config that forces the **exact Arguzz
  value/word** at the **same instruction step**:
  - `COMP_OUT_MOD`@add → force add rd WRITE = Arguzz value (from `artifacts/e1/COMP_OUT_MOD_seed*.json::mutated_value`).
  - `LOAD_VAL_MOD`@load_x → force load rd value = Arguzz value.
  - `STORE_OUT_MOD`@store → force store mem data = Arguzz value.
  - `INSTR_WORD_MOD_FULL`@add → force fetch word = Arguzz `mutated_word` (the SAME words: XOR/SLL/SUB/SLT, the rd/rs1/rs2 changes, the format changes).
- Emit a **manifest** `artifacts/e2/configs/manifest.json`: a list of
  `{run_id, run_type: "a4"|"arguzz", a4_step|arguzz_step, kind, source_e1_seed,
  forced_value_hex, config_file?}`. Validate each A4 config parses and targets the
  intended `a4_step` (assert against site card).

### P1.3 — split execute vs analyze
Refactor so the **categorizer is log-only** (no host): a local `analyze_logs.py` that
takes a directory of `<run_id>.log` (+ the manifest) and produces, per run, the same
JSON shape as E1 (`outcome_class`, `layers{intrastep/interstep/global}`, `buckets`,
`global_families`, `provenance`, and for A4 the mirror note). Reuse
`classify_run` + `categorize_failure` + `failure_rows` + `global_failure_rows` +
`touch_parse`. **No proving in the analyzer.**

### P1.4 — on-node runner (`thesis_side_experiments/pos/thesis_run_pos.sh`)
A `#!/bin/bash` script (shebang mandatory — §12.12) that, given the bundle layout:
1. `sha256sum bin/risc0-host` and assert == frozen sha (abort otherwise).
2. Export the DEFAULT_ENV flag contract.
3. Read the manifest; for each run, build the exact command (Arguzz args or
   `A4_MUTATION_CONFIG=<config>`), run the host **twice**, save `<run_id>.log` and
   `<run_id>.rerun.log`, and record a 1-line determinism check (byte-identical
   `<constraint_fail>`/`<fault>`/outcome set).
4. `pos_upload` the whole results dir (logs + determinism summary) via an EXIT trap so
   partial results survive (§ pivot 12.4).
No Python install needed on-node beyond what bakes into the host; categorization is local.

### P1.5 — bundle from frozen host
`cp frozen_host/thesis-minimal-host.e0frozen /tmp/risc0-host` then
`bash a4/pos/prepare_bundle.sh --host /tmp/risc0-host --allow-dirty`. Confirm `bundle.json`
records sha `5337f944…`. Ensure the bundle also contains `pos/thesis_run_pos.sh` +
`artifacts/e2/configs/` (configs + manifest). (If `prepare_bundle.sh` doesn't include
our extra files, stage them and add via a small `--extra` path or a thin fork in
`thesis_side_experiments/pos/` — Option B in POS_NOTES.)

### P1.6 — WSL dry-run (≤10 proofs, allowed on WSL)
Pick a **SMOKE set of ≤10 runs**: the three value-kinds (seed 0 each) + 3 INSTR_WORD_MOD
words covering the three layers — **operation** (seed 0, XOR → intrastep), **dest_reg**
(seed 2, ADD x3 → global), **operation/funct7** (seed 8, SUB → intrastep) — plus their
A4 mirrors. Run the on-node runner's command list **locally on WSL** against the frozen
host, feed logs to `analyze_logs.py`, and confirm:
- Arguzz smoke rows reproduce E1 exactly (same outcome/layers/residues).
- A4 mirror rows are categorized (record their footprints — do not gate on a specific
  A4 shape yet; that's the E2 finding).
- 2× determinism holds.

**P1 gate:** forced-value path works; configs baked + validated against site card;
`analyze_logs.py` reproduces E1 on the Arguzz smoke; runner script lint-clean with
shebang; bundle built from frozen sha; WSL dry-run green. **No POS yet.**

---

## Phase P2 — POS smoke (gated on the user's reservation)

**Reserved node = `polynize`** (Tier S AMD EPYC 9354 — fastest tier; verified Jun 12 22:58
UTC on calendar entry **1744** owner `ivgreiff`, nodes `polynize/flare/meld/octorand/opulous`,
window 22:55–04:55 UTC ≈ 6 hr). polynize is the **dedicated thesis node** — the other 4 are
the A/B campaign's; **NEVER run on flare/meld/octorand/opulous.**

**Squatter caveat (must handle):** polynize is still physically held by `spaethj`'s 56-day
allocation (`debian-bookworm`). Our reservation's start_date has passed, so claiming it via
`--allocation-duration 0` SHOULD auto-evict the squatter (§12.39) — but that's unverified for
a long-lived hold. Procedure:
1. After P1, on coinbase: `pos allocations allocate polynize` (or dispatch with
   `--allocation-duration 0`). It must succeed and show `polynize` owned by `ivgreiff`.
2. **Re-image to `debian-trixie`** (`pos.nodes.image(polynize,'debian-trixie')`) + reset —
   polynize is on bookworm (GLIBC 2.36); our host needs 2.39 (§12.30).
3. **If allocate FAILS** (spaethj not evicted): **STOP and report** — do NOT fall back to
   flare/meld/octorand/opulous (those belong to the A/B agents). Escalate to the user.

Composer then, on `coinbase` (in tmux):
1. `scp -P 10022` the bundle to coinbase (or build there from the shipped frozen host).
2. `source /srv/testbed/pos/cli/venv3/bin/activate`; verify the node is free
   (`pos allocations list`, `pos nodes list`).
3. Dispatch the **same SMOKE set** with **`--allocation-duration 0`**, image
   `debian-trixie`, `--await`. (If reusing `dispatch_pos.py`, ensure it runs our
   `thesis_run_pos.sh`, not the A4 fuzzer; otherwise use the thin thesis dispatch.)
4. Collect logs; run `analyze_logs.py` locally.

**P2 gate (POS≡WSL):** the POS smoke logs categorize **identically** to the P1 WSL
dry-run (same outcome_class, same layer counts, same residues for every smoke run), and
2× determinism holds on-node. This certifies the POS path before the full E2/E3 matrices.

---

## After E2-PREP
Once P1+P2 are green, the **full E2** (all A4 mirrors of every E1 layer-row) and **E3**
(SUR rd-only/rs1-only/rs2-only, per the updated plan §E3) are just larger manifests
through the **same validated path** — one dispatch per reservation window on the
dedicated fast node. Report POS≡WSL evidence and the first A4-vs-Arguzz footprint deltas.
