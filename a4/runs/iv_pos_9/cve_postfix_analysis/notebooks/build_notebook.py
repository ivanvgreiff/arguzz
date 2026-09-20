#!/usr/bin/env python3
"""Build cve_comparison.ipynb from cells. Run, then execute with nbconvert --to html.
Keeps the notebook itself terse; all data access goes through lib.data_access (read-only)."""
import nbformat as nbf
ANCHOR = "/root/arguzz/a4/runs/iv_pos_9/cve_postfix_analysis"
nb = nbf.v4.new_notebook()
C = []
md = lambda s: C.append(nbf.v4.new_markdown_cell(s))
co = lambda s: C.append(nbf.v4.new_code_cell(s))

md("""# rs1==rs2 CVE — post-fix variant comparison

**Question:** after the step-domain fix, how do the fuzzing variants compare at *finding* the rs1==rs2
divide CVE (CVE-2025-52484 / risc0 #3181)?

**Data provenance (see `DATA_PROVENANCE.md`):** every dataset is opened **read-only** via
`lib.data_access.open_ro` (`mode=ro&immutable=1`). NEW data (this campaign) is in `data/`; EXISTING data
(the original race: uniform, V5, pre-fix cTS/Hybrid) is read **in place, never edited/moved**, from
`../race/cve_results`. Binaries: **B2** = vulnerable, no A4 handlers; **B3** = vulnerable + 3 A4 handlers
(divide trace-confirmed at the same steps 444/449).

**Metric:** *CVE candidate* = `INSTR_WORD_MOD` accept at the divide steps 444/449 (binary-invariant Arguzz
surface; comparable across all variants). Candidates are confirmed CVE vs benign by the replay-oracle
(committed output 0=remu / 9000028=divu / 1=both); uniform's candidates were historically all CVE.""")

co(f"""import sys; sys.path.insert(0, {ANCHOR!r})
%matplotlib inline
import matplotlib.pyplot as plt, pandas as pd
from lib import data_access as D, cve_metrics as M
FIG = {ANCHOR!r} + '/figures'
print('seeds present per source:')
for s in D.SOURCES:
    print(f'  {{s.key:22}} {{s.origin:9}} {{s.binary:3}} valid={{s.valid_for_cve:12}} seeds={{sorted(s.db_paths())}}')""")

md("## 1. The comparison table (CVE candidates, all variants)")
co("""rows = M.variant_table()
df = pd.DataFrame([{
    'variant': r['label'], 'origin': r['origin'], 'binary': r['binary'], 'valid_for_CVE': r['valid'],
    'data_source': r['data_source'], 'seeds': len(r['seeds_present']), 'divide_shots': r['iwmod_div_attempts'],
    'CVE_candidates': r['cve_candidates'], 'per_seed': r['per_seed_cand'], 'total_accepts': r['accepts'],
} for r in rows]).set_index('variant')
print("data_source: 'db' = read from downloaded/existing DB; 'precomputed' = interim on-node value (full DB still downloading)")
df""")

md("""## 2. Headline — CVE candidates per variant
The unconfounded result. Pre-fix cTS/Hybrid (confounded) sat at 0 purely from the step-domain bug;
post-fix they actually compete.""")
co("""order = ['V6_uniform (baseline)','V6_cTS (post-fix)','Hybrid (post-fix, B2)','Hybrid (clean, B3)',
         'V5_control (A4)','V6_cTS (PRE-fix, confounded)','Hybrid (PRE-fix, confounded)']
d = df.reindex([o for o in order if o in df.index])
colors = ['#888' if 'uniform' in v else '#d62728' if 'PRE-fix' in v else '#2ca02c' if 'cTS (post' in v
          else '#1f77b4' if 'Hybrid' in v else '#9467bd' for v in d.index]
fig, ax = plt.subplots(figsize=(10,4.5))
b = ax.bar(range(len(d)), d['CVE_candidates'], color=colors)
ax.set_xticks(range(len(d))); ax.set_xticklabels(d.index, rotation=30, ha='right')
ax.set_ylabel('CVE candidates (6 seeds, N=5000)'); ax.set_title('CVE-finding by variant (post-fix)')
for i,(v,n) in enumerate(zip(d.index, d['CVE_candidates'])):
    ax.text(i, n+0.1, f'{n}\\n({d.loc[v,"seeds"]}s)', ha='center', fontsize=8)
plt.tight_layout(); plt.savefig(FIG+'/01_cve_candidates.png', dpi=110); plt.show()""")

md("""## 3. Targeting vs yield — does the smart bandit aim more shots at the divide?
The bandit (cTS) *does* aim more `INSTR_WORD_MOD` shots at the divide than uniform, but the per-shot
accept rate is similar, so yield (candidates) doesn't exceed uniform.""")
co("""d2 = df[df['valid_for_CVE'].isin(['YES','ARGUZZ-ONLY'])].reindex(
        [o for o in order if o in df.index and df.loc[o,'valid_for_CVE'] in ('YES','ARGUZZ-ONLY')])
fig, ax = plt.subplots(figsize=(9,4.5)); x=range(len(d2)); w=0.38
ax.bar([i-w/2 for i in x], d2['divide_shots'], w, label='divide shots (IWmod@444/449)', color='#aec7e8')
ax.bar([i+w/2 for i in x], d2['CVE_candidates'], w, label='CVE candidates', color='#d62728')
ax.set_xticks(list(x)); ax.set_xticklabels(d2.index, rotation=20, ha='right'); ax.legend()
ax.set_title('Divide targeting (shots) vs CVE yield (candidates)')
plt.tight_layout(); plt.savefig(FIG+'/02_targeting_vs_yield.png', dpi=110); plt.show()""")

md("""## 4. The 3-kind decontamination (Hybrid: B2 vs B3)
B2 silently skips 3 A4 mutation kinds → fake 100%-accept no-ops. B3 fixes them. Total accepts/seed
collapse ~40× on the clean binary — i.e., most of B2-Hybrid's "accepts" were artifacts, not findings.""")
co("""b2=M.per_seed_field('hybrid_B2_postfix','accepts'); b3=M.per_seed_field('hybrid_B3_clean','accepts')
print('Hybrid-B2 accepts/seed:', b2); print('Hybrid-B3 accepts/seed:', b3)
if b2 and b3:
    seeds=sorted(set(b2)|set(b3)); fig,ax=plt.subplots(figsize=(8,4)); x=range(len(seeds)); w=.38
    ax.bar([i-w/2 for i in x],[b2.get(s,0) for s in seeds],w,label='Hybrid-B2 (contaminated)',color='#ff9896')
    ax.bar([i+w/2 for i in x],[b3.get(s,0) for s in seeds],w,label='Hybrid-B3 (clean)',color='#2ca02c')
    ax.set_xticks(list(x)); ax.set_xticklabels(seeds); ax.set_xlabel('seed'); ax.set_ylabel('total accepts')
    ax.set_title('Decontamination: Hybrid accepts per seed (B2 vs B3)'); ax.legend()
    plt.tight_layout(); plt.savefig(FIG+'/03_decontamination.png',dpi=110); plt.show()
else:
    print('(B3 data partial — graph fills in after the last seeds download)')""")

md("""## 5. Before / after the fix (cTS & Hybrid)
Pre-fix (EXISTING, confounded) the divide-targeted INSTR_WORD accepts were 0 (arms mis-aimed to lw/ori at
436/441). Post-fix (NEW) they land on the real divides.""")
co("""pairs=[('V6_cTS (PRE-fix, confounded)','V6_cTS (post-fix)'),('Hybrid (PRE-fix, confounded)','Hybrid (post-fix, B2)')]
fig,ax=plt.subplots(figsize=(7,4)); x=range(len(pairs)); w=.38
ax.bar([i-w/2 for i in x],[df.loc[a,'CVE_candidates'] if a in df.index else 0 for a,_ in pairs],w,label='pre-fix',color='#d62728')
ax.bar([i+w/2 for i in x],[df.loc[b,'CVE_candidates'] if b in df.index else 0 for _,b in pairs],w,label='post-fix',color='#2ca02c')
ax.set_xticks(list(x)); ax.set_xticklabels(['V6_cTS','Hybrid']); ax.set_ylabel('CVE candidates'); ax.legend()
ax.set_title('Step-domain fix effect (CVE candidates)')
plt.tight_layout(); plt.savefig(FIG+'/04_before_after.png',dpi=110); plt.show()""")

md("""## 6. Findings — ALL 6 SEEDS COMPLETE (candidate-level; replay-oracle confirmation pending)
- **V6_cTS = V6_uniform = 9 candidates — tied.** The bandit aims *more* divide shots (284 vs 232) but the
  per-shot accept rate is similar, so it does **not** out-yield dumb uniform. Pre-fix "cTS=0" was purely
  the step-domain confound; removing it makes cTS *competitive with*, not *superior to*, uniform.
- **Hybrid finds ~0–3 regardless of binary** (Hybrid-B2 = 3, Hybrid-B3 clean = **0**) — far below cTS/uniform.
  It splits its budget across the Arguzz + A4 surfaces, so its divide-shots (~115) are well under pure-cTS
  (284). **Decontaminating the A4 surface did NOT redirect effort to the CVE arm** (the bandit reward is
  coverage-based, blind to soundness) — clean Hybrid still found 0.
- **Decontamination confirmed**: B3-Hybrid accepts ≈ 27/seed vs B2-Hybrid ≈ 970/seed (**~36×** drop) — i.e.
  ~96% of B2-Hybrid's "accepts" were the 3-kind silent-skip artifacts, not findings.
- **V5 (A4) = 0** — structurally can't surface this Arguzz-class bug.

**Bottom line:** post-fix and unconfounded, the *smart* variants do **not** beat dumb uniform on this CVE —
cTS ties it, Hybrid trails it, A4 can't touch it. The step-domain fix's real contribution was removing a
spurious "cTS/Hybrid = 0" that had made cTS look catastrophically worse than it is.

**Caveats:** these are *candidates*, not replay-confirmed CVEs — run the replay-oracle to classify committed
output (0=remu / 9000028=divu / 1=both vs 9000027=benign). uniform's 9 were historically all CVE; cTS's 9
need the same confirmation.

**Data provenance (2026-06-29):** the NEW rows now read the **downloaded DBs** in `data/` (not precompute).
All 18 DBs were verified before use — integrity_check ok, 5000 muts each, path-seed == in-DB seed, and the
binary-identity fingerprint confirmed (B2 `risc0-host` vs B3 `b3_risc0-host`; on B2 the 3 A4 kinds are
silent-skip `live=0`, on B3 the handlers fire `live≈115`). The DB-computed per-seed candidates / div-attempts /
accepts reproduce the earlier on-node precompute **exactly** (cTS 0,2,3,2,0,2=9; Hybrid-B2 0,0,1,1,1,0=3;
Hybrid-B3 all 0). See `data/MANIFEST.md` (sha256) and `notebooks/cve_comparison_PRECOMPUTE_SNAPSHOT.*`.""")

md("""## 7. Where in the campaign each CVE candidate was found (campaign indices)

For every variant, the **campaign index** = the mutation `id` (1-based position within that seed's N=5000
run) of each accepted `INSTR_WORD_MOD` at a divide step (444=remu / 449=divu) — i.e. exactly where in the
run that bug-find landed. Empty list = that seed found none. (DB-only; not derivable from precompute.)""")
co("""idx_keys = [('V6_uniform (baseline)','v6_uniform_baseline'),
            ('V6_cTS (post-fix)','v6_cTS_postfix'),
            ('Hybrid (post-fix, B2)','hybrid_B2_postfix'),
            ('Hybrid (clean, B3)','hybrid_B3_clean'),
            ('V5_control (A4)','v5_control')]
rows=[]
for label,key in idx_keys:
    ix = M.cve_candidate_indices(key)            # {seed:[ids]}
    total = sum(len(v) for v in ix.values())
    rows.append({'variant':label,'total_finds':total,
                 **{f'seed{seed}':(', '.join(map(str,ix.get(seed,[]))) or '—') for seed in sorted(ix)}})
idf = pd.DataFrame(rows).set_index('variant')
print('Each cell = campaign indices (mutation id, 1..5000) where an accepted INSTR_WORD_MOD@444/449 fired.')
idf""")

nb.cells = C
nbf.write(nb, ANCHOR + "/notebooks/cve_comparison.ipynb")
print("wrote", ANCHOR + "/notebooks/cve_comparison.ipynb")
