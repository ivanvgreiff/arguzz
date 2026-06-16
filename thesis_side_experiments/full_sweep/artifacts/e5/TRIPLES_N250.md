# E5 — Full (intrastep, interstep, global) triple distributions (N=250/type)

Distinct-constraint counts per layer, low/high limbs consolidated (`MemoryWrite:99`+`:100` = 1, `IsRead:79`+`:80` = 1). Global counts distinct families (memory/cycle/register).

All rates/means use the **effective-trials denominator = applied & non-crashed**, so neither crashes nor not-applied runs distort them.

**Applied** = the mutation actually ran: Arguzz emits `<fault>` only when the injection kind matched the instruction at the step; A4 emits `<a4_config_loaded>`. **Not applied** = Arguzz no-op (injection kind didn't match the instruction) OR A4 had no valid target transaction at the sampled site (so no config was built — A4's applicability limit, the mirror of Arguzz no-ops). These never ran a mutation, so they are NOT real `(0,0,0)` outcomes. **Errored/no-constraints-tested** = prover error (`PROVE_ERROR`), preflight/other crash, or verify-reject: the prover aborted before evaluating constraints, so there is no `(a,b,c)` data.

Metrics per type (and pooled per fuzzer): layer-fire rates, single-constraint rate, mean constraints/layer. Then the full triple enumeration.

Bucketing: intrastep `{0, 1, c=≥2}` · interstep `{0, 1}` · global `{0, 1, 2}` (raw).

## SUMMARY — layer-fire rates for every mutation

One row per fuzzer×mutation. Percentages use the **tested-trial denominator** (mutation applied AND constraints evaluated; excludes not-applied and errored/no-constraint-data). The three layer columns are independent binaries (can overlap → a row need not sum to 100%). **none %** = fraction with a genuine `(0,0,0)` (zero constraints broken). Low/high limbs are consolidated to one constraint throughout.

| fuzzer | mutation | n(tested) | local (intra) % | local (inter) % | global % | none % |
|---|---|---|---|---|---|---|
| arguzz | **ALL (pooled)** | 1670 | 88.9 | 55.4 | 77.2 | 2.2 |
| a4 | **ALL (pooled)** | 2067 | 94.7 | 22.6 | 91.2 | 0.0 |
| a4 | COMP_OUT_MOD | 228 | 100.0 | 0.0 | 100.0 | 0.0 |
| a4 | INSTR_TYPE_MOD | 249 | 100.0 | 6.0 | 35.7 | 0.0 |
| a4 | INSTR_WORD_MOD_FULL | 250 | 100.0 | 3.6 | 100.0 | 0.0 |
| a4 | INSTR_WORD_MOD_SUR · funct3_xor | 250 | 100.0 | 0.0 | 100.0 | 0.0 |
| a4 | LOAD_VAL_MOD | 231 | 100.0 | 0.0 | 100.0 | 0.0 |
| a4 | MEM_VAL_MOD | 250 | 97.2 | 88.8 | 100.0 | 0.0 |
| a4 | PRE_EXEC_REG_MOD · next_read | 221 | 53.8 | 100.0 | 90.5 | 0.0 |
| a4 | PRE_EXEC_REG_MOD · prev_write | 138 | 100.0 | 0.0 | 100.0 | 0.0 |
| a4 | STORE_OUT_MOD | 250 | 100.0 | 0.0 | 100.0 | 0.0 |
| arguzz | BR_NEG_COND | 62 | 100.0 | 0.0 | 100.0 | 0.0 |
| arguzz | COMP_OUT_MOD | 122 | 100.0 | 0.0 | 0.8 | 0.0 |
| arguzz | INSTR_WORD_MOD | 166 | 54.2 | 1.8 | 75.3 | 4.2 |
| arguzz | LOAD_VAL_MOD | 25 | 100.0 | 0.0 | 4.0 | 0.0 |
| arguzz | POST_EXEC_MEM_MOD | 235 | 91.1 | 99.1 | 90.6 | 0.0 |
| arguzz | POST_EXEC_PC_MOD | 144 | 75.0 | 0.0 | 78.5 | 20.8 |
| arguzz | POST_EXEC_REG_MOD | 227 | 92.5 | 100.0 | 91.2 | 0.0 |
| arguzz | PRE_EXEC_MEM_MOD | 232 | 93.5 | 99.1 | 92.7 | 0.0 |
| arguzz | PRE_EXEC_PC_MOD | 139 | 95.7 | 0.0 | 99.3 | 0.0 |
| arguzz | PRE_EXEC_REG_MOD | 232 | 93.5 | 100.0 | 91.8 | 0.0 |
| arguzz | STORE_OUT_MOD | 86 | 100.0 | 0.0 | 1.2 | 0.0 |

---

## AGGREGATE — by fuzzer (all types pooled, tested trials)

Pooled over every **tested** run (mutation applied AND constraints evaluated) of that fuzzer; micro-average, weighted by how often each type is tested. Excludes not-applied (no-ops / config errors) and errored/no-constraint-data (prove-errors, crashes, verify-rejects).

### arguzz — all mutations
- Denominator = **tested trials** (mutation applied AND constraints evaluated): **1670**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 88.9% | 55.4% | 77.2% | 2.2% |

- **Single-constraint rate** (exactly 1 broken across all layers): **23.2%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 1670 tested trials, includes the zeros): intra **1.99** · interstep **0.55** · global **1.28**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **2.24** (n=1484) · interstep **1.00** (n=925) · global **1.66** (n=1289)

### a4 — all mutations
- Denominator = **tested trials** (mutation applied AND constraints evaluated): **2067**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 94.7% | 22.6% | 91.2% | 0.0% |

- **Single-constraint rate** (exactly 1 broken across all layers): **1.6%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 2067 tested trials, includes the zeros): intra **1.27** · interstep **0.23** · global **0.93**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **1.35** (n=1958) · interstep **1.00** (n=467) · global **1.02** (n=1886)

---

## a4 · COMP_OUT_MOD

- n = **250** | not applied = **22** (no valid A4 target at site (no config built)) | errored/no-constraints-tested = **0**  | **tested = 228**

- Denominator = **tested trials** (mutation applied AND constraints evaluated): **228**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 100.0% | 0.0% | 100.0% | 0.0% |

- **Single-constraint rate** (exactly 1 broken across all layers): **0.0%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 228 tested trials, includes the zeros): intra **1.00** · interstep **0.00** · global **1.00**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **1.00** (n=228) · interstep — (n=0) · global **1.00** (n=228)

**Raw triples `(intra, inter, global)`** (over tested trials):

| (intra, inter, global) | count |
|---|---|
| (1, 0, 1) | 228 |

**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**

| (intra, inter, global) | count |
|---|---|
| (1, 0, 1) | 228 |

## a4 · INSTR_TYPE_MOD

- n = **250** | not applied = **0** (no valid A4 target at site (no config built)) | errored/no-constraints-tested = **1** {'VERIFY_REJECT': 1} | **tested = 249**

- Denominator = **tested trials** (mutation applied AND constraints evaluated): **249**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 100.0% | 6.0% | 35.7% | 0.0% |

- **Single-constraint rate** (exactly 1 broken across all layers): **5.2%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 249 tested trials, includes the zeros): intra **2.78** · interstep **0.06** · global **0.43**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **2.78** (n=249) · interstep **1.00** (n=15) · global **1.19** (n=89)

**Raw triples `(intra, inter, global)`** (over tested trials):

| (intra, inter, global) | count |
|---|---|
| (2, 0, 0) | 147 |
| (2, 0, 1) | 23 |
| (3, 0, 1) | 23 |
| (1, 0, 0) | 13 |
| (3, 1, 2) | 9 |
| (4, 0, 1) | 8 |
| (2, 1, 2) | 5 |
| (7, 0, 1) | 5 |
| (3, 0, 2) | 2 |
| (9, 0, 1) | 2 |
| (10, 0, 1) | 2 |
| (11, 0, 1) | 2 |
| (20, 0, 1) | 2 |
| (4, 1, 2) | 1 |
| (5, 0, 1) | 1 |
| (6, 0, 1) | 1 |
| (8, 0, 1) | 1 |
| (14, 0, 1) | 1 |
| (24, 0, 1) | 1 |

**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**

| (intra, inter, global) | count |
|---|---|
| (c, 0, 0) | 147 |
| (c, 0, 1) | 72 |
| (c, 1, 2) | 15 |
| (1, 0, 0) | 13 |
| (c, 0, 2) | 2 |

## a4 · INSTR_WORD_MOD_FULL

- n = **250** | not applied = **0** (no valid A4 target at site (no config built)) | errored/no-constraints-tested = **0**  | **tested = 250**

- Denominator = **tested trials** (mutation applied AND constraints evaluated): **250**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 100.0% | 3.6% | 100.0% | 0.0% |

- **Single-constraint rate** (exactly 1 broken across all layers): **0.0%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 250 tested trials, includes the zeros): intra **1.86** · interstep **0.04** · global **1.06**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **1.86** (n=250) · interstep **1.00** (n=9) · global **1.06** (n=250)

**Raw triples `(intra, inter, global)`** (over tested trials):

| (intra, inter, global) | count |
|---|---|
| (2, 0, 1) | 198 |
| (1, 0, 1) | 36 |
| (2, 1, 2) | 9 |
| (2, 0, 2) | 7 |

**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**

| (intra, inter, global) | count |
|---|---|
| (c, 0, 1) | 198 |
| (1, 0, 1) | 36 |
| (c, 1, 2) | 9 |
| (c, 0, 2) | 7 |

## a4 · INSTR_WORD_MOD_SUR · funct3_xor

- n = **250** | not applied = **0** (no valid A4 target at site (no config built)) | errored/no-constraints-tested = **0**  | **tested = 250**

- Denominator = **tested trials** (mutation applied AND constraints evaluated): **250**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 100.0% | 0.0% | 100.0% | 0.0% |

- **Single-constraint rate** (exactly 1 broken across all layers): **0.0%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 250 tested trials, includes the zeros): intra **1.00** · interstep **0.00** · global **1.00**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **1.00** (n=250) · interstep — (n=0) · global **1.00** (n=250)

**Raw triples `(intra, inter, global)`** (over tested trials):

| (intra, inter, global) | count |
|---|---|
| (1, 0, 1) | 250 |

**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**

| (intra, inter, global) | count |
|---|---|
| (1, 0, 1) | 250 |

## a4 · LOAD_VAL_MOD

- n = **250** | not applied = **19** (no valid A4 target at site (no config built)) | errored/no-constraints-tested = **0**  | **tested = 231**

- Denominator = **tested trials** (mutation applied AND constraints evaluated): **231**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 100.0% | 0.0% | 100.0% | 0.0% |

- **Single-constraint rate** (exactly 1 broken across all layers): **0.0%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 231 tested trials, includes the zeros): intra **1.00** · interstep **0.00** · global **1.00**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **1.00** (n=231) · interstep — (n=0) · global **1.00** (n=231)

**Raw triples `(intra, inter, global)`** (over tested trials):

| (intra, inter, global) | count |
|---|---|
| (1, 0, 1) | 231 |

**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**

| (intra, inter, global) | count |
|---|---|
| (1, 0, 1) | 231 |

## a4 · MEM_VAL_MOD

- n = **250** | not applied = **0** (no valid A4 target at site (no config built)) | errored/no-constraints-tested = **0**  | **tested = 250**

- Denominator = **tested trials** (mutation applied AND constraints evaluated): **250**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 97.2% | 88.8% | 100.0% | 0.0% |

- **Single-constraint rate** (exactly 1 broken across all layers): **0.0%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 250 tested trials, includes the zeros): intra **0.97** · interstep **0.89** · global **1.00**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **1.00** (n=243) · interstep **1.00** (n=222) · global **1.00** (n=250)

**Raw triples `(intra, inter, global)`** (over tested trials):

| (intra, inter, global) | count |
|---|---|
| (1, 1, 1) | 215 |
| (1, 0, 1) | 28 |
| (0, 1, 1) | 7 |

**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**

| (intra, inter, global) | count |
|---|---|
| (1, 1, 1) | 215 |
| (1, 0, 1) | 28 |
| (0, 1, 1) | 7 |

## a4 · PRE_EXEC_REG_MOD · next_read

- n = **250** | not applied = **29** (no valid A4 target at site (no config built)) | errored/no-constraints-tested = **0**  | **tested = 221**

- Denominator = **tested trials** (mutation applied AND constraints evaluated): **221**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 53.8% | 100.0% | 90.5% | 0.0% |

- **Single-constraint rate** (exactly 1 broken across all layers): **9.5%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 221 tested trials, includes the zeros): intra **0.62** · interstep **1.00** · global **0.90**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **1.16** (n=119) · interstep **1.00** (n=221) · global **1.00** (n=200)

**Raw triples `(intra, inter, global)`** (over tested trials):

| (intra, inter, global) | count |
|---|---|
| (1, 1, 1) | 114 |
| (0, 1, 1) | 81 |
| (0, 1, 0) | 21 |
| (2, 1, 1) | 2 |
| (4, 1, 1) | 1 |
| (7, 1, 1) | 1 |
| (9, 1, 1) | 1 |

**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**

| (intra, inter, global) | count |
|---|---|
| (1, 1, 1) | 114 |
| (0, 1, 1) | 81 |
| (0, 1, 0) | 21 |
| (c, 1, 1) | 5 |

## a4 · PRE_EXEC_REG_MOD · prev_write

- n = **250** | not applied = **112** (no valid A4 target at site (no config built)) | errored/no-constraints-tested = **0**  | **tested = 138**

- Denominator = **tested trials** (mutation applied AND constraints evaluated): **138**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 100.0% | 0.0% | 100.0% | 0.0% |

- **Single-constraint rate** (exactly 1 broken across all layers): **0.0%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 138 tested trials, includes the zeros): intra **1.00** · interstep **0.00** · global **1.00**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **1.00** (n=138) · interstep — (n=0) · global **1.00** (n=138)

**Raw triples `(intra, inter, global)`** (over tested trials):

| (intra, inter, global) | count |
|---|---|
| (1, 0, 1) | 138 |

**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**

| (intra, inter, global) | count |
|---|---|
| (1, 0, 1) | 138 |

## a4 · STORE_OUT_MOD

- n = **250** | not applied = **0** (no valid A4 target at site (no config built)) | errored/no-constraints-tested = **0**  | **tested = 250**

- Denominator = **tested trials** (mutation applied AND constraints evaluated): **250**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 100.0% | 0.0% | 100.0% | 0.0% |

- **Single-constraint rate** (exactly 1 broken across all layers): **0.0%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 250 tested trials, includes the zeros): intra **1.00** · interstep **0.00** · global **1.00**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **1.00** (n=250) · interstep — (n=0) · global **1.00** (n=250)

**Raw triples `(intra, inter, global)`** (over tested trials):

| (intra, inter, global) | count |
|---|---|
| (1, 0, 1) | 250 |

**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**

| (intra, inter, global) | count |
|---|---|
| (1, 0, 1) | 250 |

## arguzz · BR_NEG_COND

- n = **250** | not applied = **178** (Arguzz no-op (kind/instr mismatch)) | errored/no-constraints-tested = **10** {'PROVE_ERROR': 9, 'OTHER_CRASH': 1} | **tested = 62**

- Denominator = **tested trials** (mutation applied AND constraints evaluated): **62**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 100.0% | 0.0% | 100.0% | 0.0% |

- **Single-constraint rate** (exactly 1 broken across all layers): **0.0%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 62 tested trials, includes the zeros): intra **1.06** · interstep **0.00** · global **1.00**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **1.06** (n=62) · interstep — (n=0) · global **1.00** (n=62)

**Raw triples `(intra, inter, global)`** (over tested trials):

| (intra, inter, global) | count |
|---|---|
| (1, 0, 1) | 58 |
| (2, 0, 1) | 4 |

**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**

| (intra, inter, global) | count |
|---|---|
| (1, 0, 1) | 58 |
| (c, 0, 1) | 4 |

## arguzz · COMP_OUT_MOD

- n = **250** | not applied = **100** (Arguzz no-op (kind/instr mismatch)) | errored/no-constraints-tested = **28** {'PROVE_ERROR': 22, 'OTHER_CRASH': 6} | **tested = 122**

- Denominator = **tested trials** (mutation applied AND constraints evaluated): **122**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 100.0% | 0.0% | 0.8% | 0.0% |

- **Single-constraint rate** (exactly 1 broken across all layers): **91.0%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 122 tested trials, includes the zeros): intra **1.48** · interstep **0.00** · global **0.01**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **1.48** (n=122) · interstep — (n=0) · global **1.00** (n=1)

**Raw triples `(intra, inter, global)`** (over tested trials):

| (intra, inter, global) | count |
|---|---|
| (1, 0, 0) | 111 |
| (2, 0, 0) | 3 |
| (3, 0, 0) | 3 |
| (3, 0, 1) | 1 |
| (5, 0, 0) | 1 |
| (7, 0, 0) | 1 |
| (18, 0, 0) | 1 |
| (22, 0, 0) | 1 |

**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**

| (intra, inter, global) | count |
|---|---|
| (1, 0, 0) | 111 |
| (c, 0, 0) | 10 |
| (c, 0, 1) | 1 |

## arguzz · INSTR_WORD_MOD

- n = **250** | not applied = **0** (Arguzz no-op (kind/instr mismatch)) | errored/no-constraints-tested = **84** {'PROVE_ERROR': 78, 'OTHER_CRASH': 3, 'VERIFY_REJECT': 3} | **tested = 166**

- Denominator = **tested trials** (mutation applied AND constraints evaluated): **166**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 54.2% | 1.8% | 75.3% | 4.2% |

- **Single-constraint rate** (exactly 1 broken across all layers): **56.0%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 166 tested trials, includes the zeros): intra **1.07** · interstep **0.02** · global **0.78**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **1.97** (n=90) · interstep **1.00** (n=3) · global **1.04** (n=125)

**Raw triples `(intra, inter, global)`** (over tested trials):

| (intra, inter, global) | count |
|---|---|
| (0, 0, 1) | 68 |
| (1, 0, 0) | 25 |
| (1, 0, 1) | 25 |
| (2, 0, 1) | 18 |
| (0, 0, 0) | 7 |
| (2, 0, 0) | 6 |
| (3, 0, 0) | 3 |
| (3, 0, 1) | 3 |
| (4, 0, 1) | 3 |
| (2, 1, 2) | 2 |
| (6, 0, 1) | 2 |
| (0, 0, 2) | 1 |
| (1, 0, 2) | 1 |
| (1, 1, 2) | 1 |
| (31, 0, 1) | 1 |

**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**

| (intra, inter, global) | count |
|---|---|
| (0, 0, 1) | 68 |
| (c, 0, 1) | 27 |
| (1, 0, 0) | 25 |
| (1, 0, 1) | 25 |
| (c, 0, 0) | 9 |
| (0, 0, 0) | 7 |
| (c, 1, 2) | 2 |
| (0, 0, 2) | 1 |
| (1, 0, 2) | 1 |
| (1, 1, 2) | 1 |

## arguzz · LOAD_VAL_MOD

- n = **250** | not applied = **201** (Arguzz no-op (kind/instr mismatch)) | errored/no-constraints-tested = **24** {'PROVE_ERROR': 23, 'VERIFY_REJECT': 1} | **tested = 25**

- Denominator = **tested trials** (mutation applied AND constraints evaluated): **25**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 100.0% | 0.0% | 4.0% | 0.0% |

- **Single-constraint rate** (exactly 1 broken across all layers): **80.0%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 25 tested trials, includes the zeros): intra **1.44** · interstep **0.00** · global **0.04**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **1.44** (n=25) · interstep — (n=0) · global **1.00** (n=1)

**Raw triples `(intra, inter, global)`** (over tested trials):

| (intra, inter, global) | count |
|---|---|
| (1, 0, 0) | 20 |
| (3, 0, 0) | 2 |
| (2, 0, 0) | 1 |
| (3, 0, 1) | 1 |
| (5, 0, 0) | 1 |

**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**

| (intra, inter, global) | count |
|---|---|
| (1, 0, 0) | 20 |
| (c, 0, 0) | 4 |
| (c, 0, 1) | 1 |

## arguzz · POST_EXEC_MEM_MOD

- n = **250** | not applied = **0** (Arguzz no-op (kind/instr mismatch)) | errored/no-constraints-tested = **15** {'PREFLIGHT_CRASH': 15} | **tested = 235**

- Denominator = **tested trials** (mutation applied AND constraints evaluated): **235**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 91.1% | 99.1% | 90.6% | 0.0% |

- **Single-constraint rate** (exactly 1 broken across all layers): **8.9%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 235 tested trials, includes the zeros): intra **2.64** · interstep **0.99** · global **1.81**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **2.90** (n=214) · interstep **1.00** (n=233) · global **2.00** (n=213)

**Raw triples `(intra, inter, global)`** (over tested trials):

| (intra, inter, global) | count |
|---|---|
| (2, 1, 2) | 136 |
| (3, 1, 2) | 49 |
| (0, 1, 0) | 21 |
| (4, 1, 2) | 16 |
| (10, 1, 2) | 2 |
| (1, 1, 2) | 1 |
| (2, 0, 2) | 1 |
| (2, 1, 0) | 1 |
| (7, 1, 2) | 1 |
| (8, 0, 2) | 1 |
| (9, 1, 2) | 1 |
| (11, 1, 2) | 1 |
| (13, 1, 2) | 1 |
| (19, 1, 2) | 1 |
| (20, 1, 2) | 1 |
| (26, 1, 2) | 1 |

**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**

| (intra, inter, global) | count |
|---|---|
| (c, 1, 2) | 210 |
| (0, 1, 0) | 21 |
| (c, 0, 2) | 2 |
| (1, 1, 2) | 1 |
| (c, 1, 0) | 1 |

## arguzz · POST_EXEC_PC_MOD

- n = **250** | not applied = **0** (Arguzz no-op (kind/instr mismatch)) | errored/no-constraints-tested = **106** {'PROVE_ERROR': 100, 'OTHER_CRASH': 5, 'VERIFY_REJECT': 1} | **tested = 144**

- Denominator = **tested trials** (mutation applied AND constraints evaluated): **144**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 75.0% | 0.0% | 78.5% | 20.8% |

- **Single-constraint rate** (exactly 1 broken across all layers): **4.2%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 144 tested trials, includes the zeros): intra **1.34** · interstep **0.00** · global **0.78**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **1.79** (n=108) · interstep — (n=0) · global **1.00** (n=113)

**Raw triples `(intra, inter, global)`** (over tested trials):

| (intra, inter, global) | count |
|---|---|
| (2, 0, 1) | 66 |
| (1, 0, 1) | 34 |
| (0, 0, 0) | 30 |
| (0, 0, 1) | 6 |
| (3, 0, 1) | 5 |
| (2, 0, 0) | 1 |
| (4, 0, 1) | 1 |
| (6, 0, 1) | 1 |

**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**

| (intra, inter, global) | count |
|---|---|
| (c, 0, 1) | 73 |
| (1, 0, 1) | 34 |
| (0, 0, 0) | 30 |
| (0, 0, 1) | 6 |
| (c, 0, 0) | 1 |

## arguzz · POST_EXEC_REG_MOD

- n = **250** | not applied = **0** (Arguzz no-op (kind/instr mismatch)) | errored/no-constraints-tested = **23** {'PROVE_ERROR': 6, 'PREFLIGHT_CRASH': 15, 'OTHER_CRASH': 2} | **tested = 227**

- Denominator = **tested trials** (mutation applied AND constraints evaluated): **227**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 92.5% | 100.0% | 91.2% | 0.0% |

- **Single-constraint rate** (exactly 1 broken across all layers): **7.5%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 227 tested trials, includes the zeros): intra **2.50** · interstep **1.00** · global **1.82**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **2.70** (n=210) · interstep **1.00** (n=227) · global **2.00** (n=207)

**Raw triples `(intra, inter, global)`** (over tested trials):

| (intra, inter, global) | count |
|---|---|
| (2, 1, 2) | 147 |
| (3, 1, 2) | 41 |
| (0, 1, 0) | 17 |
| (4, 1, 2) | 9 |
| (7, 1, 2) | 3 |
| (2, 1, 0) | 2 |
| (12, 1, 2) | 2 |
| (3, 1, 0) | 1 |
| (6, 1, 2) | 1 |
| (10, 1, 2) | 1 |
| (13, 1, 2) | 1 |
| (14, 1, 2) | 1 |
| (19, 1, 2) | 1 |

**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**

| (intra, inter, global) | count |
|---|---|
| (c, 1, 2) | 207 |
| (0, 1, 0) | 17 |
| (c, 1, 0) | 3 |

## arguzz · PRE_EXEC_MEM_MOD

- n = **250** | not applied = **0** (Arguzz no-op (kind/instr mismatch)) | errored/no-constraints-tested = **18** {'PREFLIGHT_CRASH': 18} | **tested = 232**

- Denominator = **tested trials** (mutation applied AND constraints evaluated): **232**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 93.5% | 99.1% | 92.7% | 0.0% |

- **Single-constraint rate** (exactly 1 broken across all layers): **6.5%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 232 tested trials, includes the zeros): intra **2.52** · interstep **0.99** · global **1.85**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **2.69** (n=217) · interstep **1.00** (n=230) · global **2.00** (n=215)

**Raw triples `(intra, inter, global)`** (over tested trials):

| (intra, inter, global) | count |
|---|---|
| (2, 1, 2) | 146 |
| (3, 1, 2) | 51 |
| (0, 1, 0) | 15 |
| (4, 1, 2) | 8 |
| (2, 0, 2) | 2 |
| (2, 1, 0) | 2 |
| (1, 1, 2) | 1 |
| (7, 1, 2) | 1 |
| (10, 1, 2) | 1 |
| (11, 1, 2) | 1 |
| (12, 1, 2) | 1 |
| (13, 1, 2) | 1 |
| (19, 1, 2) | 1 |
| (26, 1, 2) | 1 |

**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**

| (intra, inter, global) | count |
|---|---|
| (c, 1, 2) | 212 |
| (0, 1, 0) | 15 |
| (c, 0, 2) | 2 |
| (c, 1, 0) | 2 |
| (1, 1, 2) | 1 |

## arguzz · PRE_EXEC_PC_MOD

- n = **250** | not applied = **0** (Arguzz no-op (kind/instr mismatch)) | errored/no-constraints-tested = **111** {'PROVE_ERROR': 104, 'OTHER_CRASH': 5, 'VERIFY_REJECT': 2} | **tested = 139**

- Denominator = **tested trials** (mutation applied AND constraints evaluated): **139**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 95.7% | 0.0% | 99.3% | 0.0% |

- **Single-constraint rate** (exactly 1 broken across all layers): **4.3%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 139 tested trials, includes the zeros): intra **1.68** · interstep **0.00** · global **0.99**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **1.75** (n=133) · interstep — (n=0) · global **1.00** (n=138)

**Raw triples `(intra, inter, global)`** (over tested trials):

| (intra, inter, global) | count |
|---|---|
| (2, 0, 1) | 81 |
| (1, 0, 1) | 44 |
| (0, 0, 1) | 6 |
| (3, 0, 1) | 5 |
| (2, 0, 0) | 1 |
| (4, 0, 1) | 1 |
| (6, 0, 1) | 1 |

**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**

| (intra, inter, global) | count |
|---|---|
| (c, 0, 1) | 88 |
| (1, 0, 1) | 44 |
| (0, 0, 1) | 6 |
| (c, 0, 0) | 1 |

## arguzz · PRE_EXEC_REG_MOD

- n = **250** | not applied = **0** (Arguzz no-op (kind/instr mismatch)) | errored/no-constraints-tested = **18** {'PROVE_ERROR': 5, 'PREFLIGHT_CRASH': 11, 'OTHER_CRASH': 2} | **tested = 232**

- Denominator = **tested trials** (mutation applied AND constraints evaluated): **232**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 93.5% | 100.0% | 91.8% | 0.0% |

- **Single-constraint rate** (exactly 1 broken across all layers): **6.5%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 232 tested trials, includes the zeros): intra **2.48** · interstep **1.00** · global **1.84**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **2.65** (n=217) · interstep **1.00** (n=232) · global **2.00** (n=213)

**Raw triples `(intra, inter, global)`** (over tested trials):

| (intra, inter, global) | count |
|---|---|
| (2, 1, 2) | 145 |
| (3, 1, 2) | 50 |
| (0, 1, 0) | 15 |
| (4, 1, 2) | 11 |
| (2, 1, 0) | 3 |
| (11, 1, 2) | 2 |
| (3, 1, 0) | 1 |
| (6, 1, 2) | 1 |
| (7, 1, 2) | 1 |
| (12, 1, 2) | 1 |
| (17, 1, 2) | 1 |
| (19, 1, 2) | 1 |

**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**

| (intra, inter, global) | count |
|---|---|
| (c, 1, 2) | 213 |
| (0, 1, 0) | 15 |
| (c, 1, 0) | 4 |

## arguzz · STORE_OUT_MOD

- n = **250** | not applied = **151** (Arguzz no-op (kind/instr mismatch)) | errored/no-constraints-tested = **13** {'PROVE_ERROR': 12, 'OTHER_CRASH': 1} | **tested = 86**

- Denominator = **tested trials** (mutation applied AND constraints evaluated): **86**

**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):

| local (intra) | interstep | global | none broken |
|---|---|---|---|
| 100.0% | 0.0% | 1.2% | 0.0% |

- **Single-constraint rate** (exactly 1 broken across all layers): **97.7%**
- **Mean constraints / layer — UNCONDITIONAL** (avg over all 86 tested trials, includes the zeros): intra **1.02** · interstep **0.00** · global **0.01**
- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; `unconditional = fire-rate × conditional`): intra **1.02** (n=86) · interstep — (n=0) · global **1.00** (n=1)

**Raw triples `(intra, inter, global)`** (over tested trials):

| (intra, inter, global) | count |
|---|---|
| (1, 0, 0) | 84 |
| (1, 0, 1) | 1 |
| (3, 0, 0) | 1 |

**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**

| (intra, inter, global) | count |
|---|---|
| (1, 0, 0) | 84 |
| (1, 0, 1) | 1 |
| (c, 0, 0) | 1 |

