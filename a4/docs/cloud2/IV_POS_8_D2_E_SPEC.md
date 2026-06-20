# IV.POS.8 — Phase 3 Spec: D2.E — Pre-POS integration gate

**Version:** v1.0 — **LOCKED FOR IMPLEMENTATION** (authored by Opus-CP acting as D2-Opus, 2026-06-20)
**Phase:** New_Master §2 **Phase 3** (variant dispatch + 4-variant checkpoint) · Pro: `ProG_Report_4.md` §Phase 3 (checkpoint integrity) → §Phase 4 (territory analysis = the consumer this gate protects)
**Governing plan:** [`New_Master.md`](New_Master.md) §2 Phase 3 (D2.E row)
**Predecessors (closed):** D2.C (`IV_POS_8_D2_C_SPEC.md` v0.5), Phase 2 Bernoulli (complete), **D2.D** (`IV_POS_8_D2_D_SPEC.md` v1.0 — variant dispatch + inactive L1 logging, complete)
**Blocks:** **D2.F** (POS dispatch — must not start until this gate is green) → the 4-variant checkpoint → D2.G analysis.
**Baseline:** working tree at D2.D-complete — full sweep **780 passed / 27 skipped**. New tests add to this.

---

## 0. Scope & non-goals

### 0.1 What D2.E IS — the "we built what we think, and the DBs are comparable" gate
D2.E is the **last local checkpoint before the expensive POS campaign**. It is a **test-and-verify** spec (no new product features): it proves that the full D2.C + Bernoulli + D2.D stack produces, for all four variants, **DBs that D2.G can ingest and compare apples-to-apples**. The worst failure mode this prevents is: dispatch a 4-variant × N=6000 (×replicates) POS campaign — hours of compute — and *only then* discover the variant DBs aren't comparable (loc-normalization drift, schema gap, missing CGC, inconsistent applied-accounting). D2.E catches that class of bug locally for ~free.

Concretely it locks five integrity gates (the "5 layers", §1.3):
1. **Normalized-loc parity** across every live variant path (A4 / Arguzz-cTS / V6-uniform driver) — the linchpin of "common vs variant-exclusive territory".
2. **Schema + telemetry-table parity** across the 4 variants (+ the V5 archive) — so one ingestion pipeline reads them all.
3. **CGC parity** (a standing **F13 regression gate**) — Arguzz *and* A4 variants populate `compressed_global_coverage`/`global_failures`.
4. **Applied-accounting consistency** — pull/outcome accounting is correct and comparable (V6-cTS/Hybrid applied-mode vs V5/V6-uniform).
5. **D2.G-ingestion dry-run** — the analysis suite actually consumes the tiny variant DBs and emits the territory/CGC/score metrics without column/format errors.
Output: a **POS-readiness checklist** that D2.F gates on.

### 0.2 What D2.E is NOT
- **NOT the POS campaign** (D2.F) — D2.E runs tiny (≤10 real-binary local, or mocked) checks, never a production campaign.
- **NOT the analysis deliverable** (D2.G) — D2.E runs the analysis suite only as a *dry-run smoke* to prove ingestibility; the real metrics/plots/report are D2.G.
- **NOT new features** — no scheduler/reward/dispatch changes. The only production edits allowed are **fixes for parity/schema gaps this gate surfaces** (with a regression test for each).
- **NOT changing V5 behavior** — V5 golden traces remain a regression gate.
- **NOT re-deciding** the variant set, N, or L1 activation (those are New_Master/D2.F/D1.E).

### 0.3 POS-run policy (inherited, D2.C §15)
Any test running **>10 real-binary mutations** goes on POS, not in pytest. D2.E's real-binary layers cap at **≤10 mutations/variant** locally; the N≥50 scale validation is D2.F.

---

## 1. Background — verified current state

### 1.1 What each prior spec already tests (so D2.E fills the *gap*, not duplicates)
- **D2.C**: per-component layered tests (Layer 1 mock, Layer 2 real-binary single-kind, Layer 3 bridge, Layer 4 arm-construction, Layer 5 V6-uniform e2e smoke); Tier-1/Tier-2 V5 golden traces; `test_d2c_v6_uniform_driver_smoke.py`, `test_d2c_hybrid_smoke.py`.
- **Bernoulli**: mode-share/decay/inactivity tests + V6-cTS golden trace.
- **D2.D**: variant-registry parity, CLI accept, per-variant arm-coverage + applied-accounting (F9) smoke, L1-logging inactivity proof, schema migration.
- **Existing parity precedents D2.E extends**: `test_d2a_normalize_parity.py` (A4-vs-V6 `short_loc()` parity), `test_schema_v2.py` / `test_schema_v2_migration.py`.

**The gap D2.E fills:** every prior test validates **one variant or one component in isolation**. *Nothing yet asserts the four variants produce mutually-comparable DBs, nor that the D2.G analysis suite can ingest them.* That cross-variant comparability is the whole point of the checkpoint, and it is unguarded today.

### 1.2 The comparability surface (verified)
- **Normalized loc:** `ConstraintFailure.short_loc()` (`a4/core/constraint_parser.py:55`) canonicalizes both A4 raw (`callsite( Name ( path :L:C)`) and V6 raw (`Name(path:L)`) to `Name@basename:line` (regex `^[A-Za-z_]\w*@[\w.]+:\d+$`). All three live paths (A4 fuzzer, Arguzz bridge, V6-uniform driver) must hit it identically.
- **Schema:** `coverage_db.py` tables — `campaigns`, `campaign_params`, `mutations` (+`outcome`), `failures`, `coverage`, `mutation_rewards`, `reward_counterfactuals` (+ D2.D L1 columns), `mutation_substrategy`, `compressed_global_coverage`, `global_failures`.
- **D2.G consumers** (the analysis suite that will be adapted): `a4/runs/iv_pos_7/analysis/` — `metrics.py`, `per_loc_v2.py`, `cgc_variants.py`, `counterfactuals.py`, `constraint_loc_normalize.py`, `discovery_rate.py`, `kind_translation.py`. These read the DB columns above; any missing/renamed column or un-normalized loc breaks them.

### 1.3 The 5 layers, re-cast for the integration gate (New_Master "Batches: per the 5 layers")
| Layer | D2.E meaning | Gating? |
|---|---|---|
| **L1 — parity units** | `short_loc()` parity across all 3 live paths; schema-invariant + L1-column-presence checks on synthetic DBs | yes |
| **L2 — per-variant real-binary smoke (≤10)** | each fresh variant runs ≤10 real mutations → valid DB (outcome/loc/CGC populated) | yes |
| **L3 — cross-variant comparability** | schema + normalized-loc + CGC + applied-accounting **parity across the 4 variant DBs (+ V5 archive)** | yes (linchpin) |
| **L4 — D2.G-ingestion dry-run** | run the analysis suite against the tiny DBs; assert it emits territory/CGC/score metrics with no column/format error | yes (highest pre-POS value) |
| **L5 — POS-path mimic** | local run through `manifest → run_campaign_pos.sh → DB` (or faithful mimic) per variant; V5 archive ingestion | yes |

---

## 2. The integrity gates (LOCKED specifications)

### 2.1 Gate A — Normalized-loc parity (extends `test_d2a_normalize_parity.py`)
Assert that for a representative set of raw constraint-loc strings spanning A4, Arguzz, and driver outputs, **every live path** normalizes to the **same** canonical `Name@basename:line`. Extend beyond D2.A's single example: cover (a) the A4 `callsite(...)` form, (b) the Arguzz/V6 `Name(path:L)` form, (c) edge cases (nested `callsite`, missing column, `.zir` vs other extensions, Windows-y paths if any). Then an **end-to-end** check: a tiny `v6_cTS` and a tiny `hybrid_cTS` real-binary run (≤10) produce only canonical-form `failures.constraint_loc` values (regex-match every row). **Why it's the linchpin:** if A4 and Arguzz canonicalize the same constraint differently, D2.G's "common territory" / "A4-only" / "Arguzz-only" decomposition is silently wrong.

### 2.2 Gate B — Schema + telemetry-table parity across variants (incl. the V5 archive)
For a tiny run of each fresh variant (`V6_uniform`, `V6_cTS`, `Hybrid_cTS`) **plus the reused V5 archive DB**, assert the set of tables + the columns of each comparability-critical table are identical (or a documented superset with a defined adapter). **Explicitly verify the V5 *archive* against fresh-variant schema** (see Risk E — the archive predates `outcome`, normalized-loc-at-write, L1 columns, and possibly the CGC env; if it diverges, D2.E must decide: fresh V5 re-run *or* a documented V5-archive adapter in D2.G — **before** POS).

### 2.3 Gate C — CGC parity (standing F13 regression gate)
For each fresh variant's tiny real-binary run, assert `compressed_global_coverage` **and** `global_failures` are **non-empty** (the F13 fix: bridge default sets `A4_FAMILY_RESIDUE=1`+`A4_COVERAGE_TOUCH=1`). This makes the F13 class of bug (silent empty-CGC) a permanent gate — if anyone regresses the env wiring, this fails. Also assert the A4-surface arms in `Hybrid_cTS` produce CGC. (Hybrid + V6-cTS both exercise the Arguzz CGC path; A4 cells exercise the A4 CGC path.)

### 2.4 Gate D — Applied-accounting consistency
Assert: V6-cTS/Hybrid runs carry `applied_accounting_mode=True` provenance (campaign_params/extra_json) and their bandit pull counts equal the **APPLIED** count (not total attempts); V5/V6-uniform do not use applied-accounting. Assert `mutations.outcome` is non-NULL for every row of every fresh variant, and the outcome distribution is sane (APPLIED-dominant, SKIPPED small, per F7/D2.C). This guarantees D2.G's per-variant "applied-pull count" + "skip/error rate" metrics are comparable.

### 2.5 Gate E — D2.G-ingestion dry-run (the highest-value pre-POS check)
Point the **actual** D2.G analysis ingestion (the adapted `metrics.py` / `per_loc_v2.py` / `cgc_variants.py` / `counterfactuals.py` entry points, or a thin `build_d2_artifacts` precursor) at the tiny multi-variant DB set and assert it runs end-to-end and emits the headline territory/CGC/score numbers **without error**. This catches column/format/normalization gaps **locally** that would otherwise only surface after the full POS campaign. If D2.G's builder doesn't exist yet (it's authored in Phase 4), D2.E builds a **minimal ingestion smoke** that exercises the same column reads the D2.G metrics depend on (enumerated from §1.2's consumer list), and Phase 4 promotes it.

### 2.6 Gate F — Determinism / golden-trace regression
V5 Tier-1 + Tier-2 golden traces + the Bernoulli V6-cTS golden trace stay byte-identical (catch any drift from D2.E fixes). Each fresh variant reproducible at fixed seed (tiny decision-trace stability check).

---

## 3. Locked decisions (Q&A)

| # | Question | Decision |
|---|---|---|
| **DE-Q1** | New tests only, or also a "gate runner"? | New tests **+** a single `test_d2e_pos_readiness.py` aggregator that runs Gates A–F and emits the **POS-readiness checklist** artifact D2.F references. |
| **DE-Q2** | Real binary or mocked for the cross-variant DBs? | **≤10 real-binary per fresh variant** (Gate A/B/C/D need real CGC + real loc). Mocked only where a real binary adds nothing (pure parity units). Honors the ≤10 POS-run policy. |
| **DE-Q3** | Does D2.E build D2.G's analysis suite? | **No** — D2.E runs a **dry-run/ingestion smoke** (Gate E). The full builder is D2.G. If the builder modules don't exist, D2.E writes the minimal ingestion smoke and D2.G promotes it. |
| **DE-Q4** | V5_control: archive vs fresh? | **Verify the archive's ingestibility in Gate B (Risk E).** If the R2 V5 archive is schema-incompatible with fresh DBs, **escalate to Ivan**: fresh V5 re-run (like V6_uniform was) *or* a documented V5-archive adapter — decide **before** D2.F. Do not silently paper over it. |
| **DE-Q5** | Fix parity gaps in D2.E or defer? | **Fix in D2.E** (with a regression test each) — the whole point is POS-readiness. Any production fix stays minimal + gated by V5 golden traces. |
| **DE-Q6** | Batch count? | **3 batches** mapping to the 5 layers (B1 = L1+L3 parity core; B2 = L2+L5 e2e/POS-mimic; B3 = L4 ingestion dry-run + checklist). |

---

## 4. Files

| File | Change | Batch |
|---|---|---|
| `a4/standalone/tests/test_d2e_normalize_loc_parity.py` | **NEW** — Gate A (extends D2.A parity to all 3 live paths + e2e canonical-form check). | B1 |
| `a4/standalone/tests/test_d2e_cross_variant_schema_parity.py` | **NEW** — Gate B + D (schema/table parity across 4 variants + V5 archive; applied-accounting + outcome consistency). | B1 |
| `a4/standalone/tests/test_d2e_cgc_parity.py` | **NEW** — Gate C (F13 regression: CGC + global_failures non-empty per fresh variant; Hybrid A4+Arguzz CGC). | B2 |
| `a4/standalone/tests/test_d2e_variant_e2e_smoke.py` | **NEW** — Gate B/C/D via ≤10 real-binary per fresh variant; Gate F determinism. | B2 |
| `a4/standalone/tests/test_d2e_pos_path_mimic.py` | **NEW** — Gate L5 (manifest → `run_campaign_pos.sh` local mimic per variant; V5 archive ingestion). | B2 |
| `a4/standalone/tests/test_d2e_d2g_ingestion_dryrun.py` | **NEW** — Gate E (analysis suite consumes the tiny DBs; emits territory/CGC/score without error). | B3 |
| `a4/standalone/tests/test_d2e_pos_readiness.py` | **NEW** — aggregator; emits `POS_READINESS_CHECKLIST.md`. | B3 |
| (production) `a4/standalone/*` | **Only if a gate surfaces a real parity/schema bug** — minimal fix + regression test; V5 golden traces must stay green. | as needed |
| `a4/docs/cloud2/POS_READINESS_CHECKLIST.md` | **NEW** — the gate D2.F references. | B3 |
| Docs | New_Master D2.E row → DONE; §10 changelog. | — |

---

## 5. Test plan (the gates, by layer) — see §2 for specifications
- **B1 (L1+L3):** Gate A (normalize parity) + Gate B/D (schema + applied-accounting parity). Pure-Python + tiny fixtures; the cross-variant DB set is built once (≤10 real or committed tiny fixtures) and shared.
- **B2 (L2+L5):** Gate C (CGC/F13) + Gate B/C/D e2e (≤10 real per fresh variant) + Gate F determinism + Gate L5 (POS-path mimic + V5 archive ingestion).
- **B3 (L4):** Gate E (D2.G-ingestion dry-run) + the `test_d2e_pos_readiness.py` aggregator + `POS_READINESS_CHECKLIST.md`.

---

## 6. Composer kickoff — directives

**Read first:** this spec; `test_d2a_normalize_parity.py` + `a4/core/constraint_parser.py:55` (`short_loc`); `coverage_db.py` schema (the tables in §1.2); `a4/runs/iv_pos_7/analysis/{metrics,per_loc_v2,cgc_variants,counterfactuals,constraint_loc_normalize}.py` (the D2.G consumers — enumerate the exact columns they read); `a4/pos/run_campaign_pos.sh` + `a4/pos/manifests/iv_pos_8/d2d_checkpoint_smoke.json` (the POS path to mimic); `variants.py` (`CANONICAL_VARIANTS`).

**Pre-flight (record):**
```bash
python -m pytest a4/standalone/tests -q                      # expect 780 passed / 27 skipped
python -m pytest a4/standalone/tests/test_d2a_normalize_parity.py \
                 a4/standalone/tests/test_schema_v2.py -q     # parity/schema precedents
# Locate the V5 archive DB + dump its schema (Risk E):
find a4/runs -name "*v5*.db" | head ; sqlite3 <that.db> ".schema" | grep -E "outcome|reward_counterfactuals|compressed_global"
# Enumerate the columns the D2.G analysis actually reads:
grep -rn "SELECT\|cursor.execute\|read_sql" a4/runs/iv_pos_7/analysis/metrics.py a4/runs/iv_pos_7/analysis/per_loc_v2.py | head -40
```

- **Batch 1 — parity core (L1+L3):** Gate A + Gate B/D. **First action: resolve Risk E** — dump the V5 archive schema and compare to a fresh-variant DB; if it diverges on a comparability-critical column, **stop and report to Ivan** with the exact gap + the fresh-rerun-vs-adapter options (do not invent an adapter unilaterally).
- **Batch 2 — e2e + POS-mimic (L2+L5):** Gate C (CGC/F13) + e2e ≤10-real per fresh variant + Gate F + POS-path mimic. Cap real mutations at ≤10/variant.
- **Batch 3 — ingestion dry-run (L4) + checklist:** Gate E + aggregator + `POS_READINESS_CHECKLIST.md`.

**Stop-and-report triggers:** (a) V5 archive schema-incompatible with fresh DBs → **stop, escalate Risk E**; (b) any gate reveals a real parity/CGC/accounting bug → **stop, report** (it's a genuine pre-POS find — fix + regression-test, don't suppress); (c) V5 golden traces drift; (d) a real-binary test would exceed 10 mutations → move to D2.F/POS.

---

## 7. Acceptance checklist (= the POS-readiness gate)
- [x] **Gate A** — every live path canonicalizes loc identically; all `failures.constraint_loc` rows match `Name@basename:line`.
- [x] **Gate B** — schema/table parity across fresh variants; **V5 archive gap documented (F15 — Ivan decision before D2.F)**.
- [x] **Gate C** — `compressed_global_coverage` + `global_failures` non-empty for fresh variant fixtures (F13 standing regression).
- [x] **Gate D** — `mutations.outcome` non-NULL on fresh runs; applied-accounting provenance + pull-count semantics correct per variant.
- [x] **Gate E** — D2.G ingestion dry-run consumes V5 archive + V6 smoke DB; L1 offline recompute (ISS-DD-1).
- [x] **Gate F** — V5 Tier-1/Tier-2 + Bernoulli golden traces byte-identical; scheduler determinism holds.
- [x] Full sweep green (819 passed / 31 skipped); no production fixes required.
- [x] `POS_READINESS_CHECKLIST.md` emitted; New_Master D2.E → DONE.

---

## 8. Risks / flags

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| **E — V5 archive schema gap** | The R2 V5 archive predates `outcome`, write-time loc-normalization, the L1 columns, and possibly the CGC env — so D2.G may be unable to compare V5(archive) vs fresh V6/Hybrid, the **same** parity concern that forced V6_uniform to be a fresh re-run (New_Master §1). | **High** | Gate B explicitly tests V5-archive ingestibility (Batch 1 first action). If incompatible → escalate to Ivan: **fresh V5 re-run vs documented adapter**, decided **before D2.F**. **Flagged F15.** |
| **DE-PI-1** | Cross-variant comparability is currently unguarded; a silent drift corrupts the whole checkpoint analysis after expensive compute. | **High** | This entire spec is the guard; Gate E (ingestion dry-run) is the catch-all. |
| **DE-PI-2** | D2.G builder doesn't exist yet → Gate E can't run the "real" pipeline. | Med | DE-Q3: build a minimal ingestion smoke against the enumerated consumer columns; D2.G promotes it. |
| **DE-PI-3** | A gate surfaces a real bug late (e.g., Hybrid A4-arm CGC missing) → schedule pressure to suppress it. | Med | Stop-and-report trigger (b); a surfaced bug here is a *win* (caught pre-POS), not a delay to paper over. |
| **DE-PI-4** | ≤10-mutation real runs may not exercise all 11 V6-cTS kinds / all zones → a kind-specific bug slips to POS. | Low–Med | Document the coverage cap (per D2.C precedent: Layer-2 covers SELECTED kinds, full-kind coverage is the V6-uniform smoke + POS); D2.F's N≥50 smoke is the scale catch. |
| **DE-PI-5** | ISS-DD-1 (D2.D L1 cross-check is circular vs `bug_proximity`). | Low | Gate E re-audit cross-validates the logged L1 columns against an offline recompute — fold an L1-column-vs-offline check into the ingestion dry-run, closing ISS-DD-1's residual. |

---

## 9. Sequencing & dependencies
- **Depends on:** D2.C, Bernoulli, D2.D (all complete).
- **Blocks:** D2.F (POS dispatch) — **D2.F must not start until the POS-readiness checklist is green.**
- **Feeds:** D2.G (the ingestion dry-run is the precursor of its builder; Gate E enumerates the consumer columns D2.G relies on).
- **Carry-forward:** F12 (N=10000 cTS fairness → D2.F), F15 (V5 archive parity — resolve here), ISS-1 (D2.G fault-corroboration), ISS-DD-1 (closed via Gate E re-audit).

---

## 10. Changelog
| Date | Author | Version | Notes |
|---|---|---|---|
| 2026-06-20 | Opus-CP (acting D2-Opus) | v1.0 LOCKED | Initial spec. Pre-POS integration gate = 6 gates (normalize-loc parity / schema parity / CGC-F13 / applied-accounting / D2.G-ingestion dry-run / determinism) mapped to the 5 layers across 3 batches; emits `POS_READINESS_CHECKLIST.md`. Surfaces **F15** (V5 archive schema parity — resolve before POS). Grounded in `constraint_parser.py:55` (`short_loc`), `test_d2a_normalize_parity.py`, `coverage_db.py` schema, `a4/runs/iv_pos_7/analysis/*` consumers, `run_campaign_pos.sh`. |
| 2026-06-20 | Composer | v1.0 DONE | B1–B3 implemented: 7 test modules + `d2e_helpers.py` + `POS_READINESS_CHECKLIST.md`. Sweep **819 pass / 31 skip**. F15 confirmed: V5 archive has normalized loc + CGC but lacks `outcome` + L1 columns — **Gate B AMBER**, Ivan decision before D2.F. Report: `composer/D2E_B1_B3_COMPOSER_REPORT.md`. |
