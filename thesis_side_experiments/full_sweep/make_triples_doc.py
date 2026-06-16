#!/usr/bin/env python3
"""
make_triples_doc.py — enumerate the full (intrastep, interstep, global) distinct-constraint
triple distribution for every mutation type-variant, from the retained E5 atoms.

NO re-proving. Pure re-aggregation of artifacts/e5/atoms_n250/*.json.

Two layers of reporting per type-variant:
  1) RAW enumeration   : every (a,b,c) triple actually observed + its frequency
                         (low/high limbs consolidated; counts are distinct (constraint,cycle))
  2) BUCKETED summary  : intrastep {0,1,c>=2}, interstep {0,1}, global {0,1,2}

Counting rules (decided with user):
  * distinct constraint = unique (normalized_loc, cycle); normalized_loc strips ALL :NN
    numbers, so MemoryWrite:99 + :100 (low/high limbs) collapse to ONE, IsRead:79+:80 collapse,
    etc. Genuine multi-cycle / multi-check breaks stay separate.
  * global slot counts distinct FAMILIES (memory / cycle / register).
  * crashed runs have no constraint data -> reported separately, not in the triple table.
  * Arguzz instruction-class kinds (COMP/LOAD/STORE/BR) often no-op; triples are enumerated
    over FIRED & non-crashed runs. silent no-ops + crashes are reported as separate counts.
"""
import json, glob, re, os
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ATOMS = os.path.join(HERE, "artifacts", "e5", "atoms_n250")
OUT_MD = os.path.join(HERE, "artifacts", "e5", "TRIPLES_N250.md")

LAYERS = ["intrastep-local", "interstep-local", "global"]


def norm(loc):
    """Strip all :NN line/col numbers to consolidate low/high limb pairs."""
    return re.sub(r":\d+", "", loc or "")


def fired(a):
    """Did the mutation actually apply?
    Arguzz: a <fault> tag is emitted only when the injection kind matched the
            instruction at the step (else a silent no-op).
    A4:     <a4_config_loaded> means the config JSON loaded and the mutation
            applied; <a4_error> (e.g. 'failed to read config / Is a directory')
            means the mutation NEVER applied (harness path bug) -> not applied.
    """
    fi = a.get("fault_info") or ""
    if a["fuzzer"] == "a4":
        return "<a4_config_loaded" in fi
    return "<fault" in fi


def not_applied_reason(fuzzer):
    return ("no valid A4 target at site (no config built)" if fuzzer == "a4"
            else "Arguzz no-op (kind/instr mismatch)")


# Outcome taxonomy (source of truth = outcome_class + constraints[], both validated).
# crashed/layers derived fields in atoms are NOT trusted (PROVE_ERROR bug).
TESTED = {"CONSTRAINT_REJECT", "GLOBAL_REJECT", "ACCEPTED"}   # constraints actually evaluated
NO_DATA = {"PROVE_ERROR", "PREFLIGHT_CRASH", "OTHER_CRASH", "VERIFY_REJECT"}  # nothing tested


def category(a):
    """Partition every atom by what the prover actually did."""
    if not fired(a):
        return "not_applied"          # mutation never ran (no-op / config error)
    oc = a.get("outcome_class")
    if oc in TESTED:
        return "tested"               # constraints evaluated -> (a,b,c) meaningful
    if oc in NO_DATA:
        return "no_data"              # prover errored/crashed -> no constraints tested
    return "other"                    # should never happen


def distinct_counts(a):
    """Return (intrastep, interstep, global) distinct consolidated counts."""
    cons = a.get("constraints") or []
    out = []
    for layer in LAYERS:
        items = [c for c in cons if c.get("layer") == layer]
        keys = set((norm(c.get("full_loc", "")), c.get("cycle")) for c in items)
        out.append(len(keys))
    return tuple(out)


def bucket_intra(n):
    return "c" if n >= 2 else str(n)


def _cond_mean(triples, idx):
    """E[count in layer | count in layer >= 1] = mean over trials where the layer fired.
    Returns (conditional_mean, n_fired). (None, 0) if the layer never fired."""
    hits = [t[idx] for t in triples if t[idx] >= 1]
    if not hits:
        return None, 0
    return sum(hits) / len(hits), len(hits)


def metrics(effective):
    """Compute layer-fire %, single-constraint %, unconditional mean-per-layer, AND
    conditional mean-per-layer (given the layer fired), over a list of effective-trial
    atoms (applied & non-crashed). Returns dict or None."""
    d = len(effective)
    if d == 0:
        return None
    triples = [distinct_counts(a) for a in effective]
    p_intra = sum(1 for t in triples if t[0] >= 1) / d
    p_inter = sum(1 for t in triples if t[1] >= 1) / d
    p_glob = sum(1 for t in triples if t[2] >= 1) / d
    p_none = sum(1 for t in triples if t == (0, 0, 0)) / d
    p_single = sum(1 for t in triples if (t[0] + t[1] + t[2]) == 1) / d
    m_intra = sum(t[0] for t in triples) / d
    m_inter = sum(t[1] for t in triples) / d
    m_glob = sum(t[2] for t in triples) / d
    # conditional means (cascade depth GIVEN that layer fired): m_layer = p_layer * cm_layer
    cm_intra, n_intra = _cond_mean(triples, 0)
    cm_inter, n_inter = _cond_mean(triples, 1)
    cm_glob, n_glob = _cond_mean(triples, 2)
    return dict(d=d, p_intra=p_intra, p_inter=p_inter, p_glob=p_glob, p_none=p_none,
                p_single=p_single, m_intra=m_intra, m_inter=m_inter, m_glob=m_glob,
                cm_intra=cm_intra, cm_inter=cm_inter, cm_glob=cm_glob,
                n_intra=n_intra, n_inter=n_inter, n_glob=n_glob)


def render_metrics(m):
    L = []
    L.append(f"- Denominator = **tested trials** (mutation applied AND constraints evaluated): **{m['d']}**")
    L.append("")
    L.append("**Layer-fire rates** (independent binaries — can overlap, don't sum to 100):")
    L.append("")
    L.append("| local (intra) | interstep | global | none broken |")
    L.append("|---|---|---|---|")
    L.append(f"| {m['p_intra']*100:.1f}% | {m['p_inter']*100:.1f}% | {m['p_glob']*100:.1f}% | {m['p_none']*100:.1f}% |")
    L.append("")
    L.append(f"- **Single-constraint rate** (exactly 1 broken across all layers): **{m['p_single']*100:.1f}%**")
    L.append(f"- **Mean constraints / layer — UNCONDITIONAL** (avg over all {m['d']} tested trials, "
             f"includes the zeros): intra **{m['m_intra']:.2f}** · interstep **{m['m_inter']:.2f}** · "
             f"global **{m['m_glob']:.2f}**")

    def cstr(cm, nf):
        return f"**{cm:.2f}** (n={nf})" if cm is not None else "— (n=0)"

    L.append(f"- **Mean constraints / layer — CONDITIONAL on that layer firing** (cascade depth; "
             f"`unconditional = fire-rate × conditional`): "
             f"intra {cstr(m['cm_intra'], m['n_intra'])} · "
             f"interstep {cstr(m['cm_inter'], m['n_inter'])} · "
             f"global {cstr(m['cm_glob'], m['n_glob'])}")
    L.append("")
    return L


def group_label(a):
    v = a.get("variant")
    return (a["fuzzer"], a["mutation_type"], v)


def main():
    atoms = [json.load(open(f)) for f in glob.glob(os.path.join(ATOMS, "*.json"))]

    groups = defaultdict(list)
    for a in atoms:
        groups[group_label(a)].append(a)

    # deterministic ordering: fuzzer, then type, then variant
    def sort_key(k):
        return (k[0], k[1], k[2] or "")

    # pooled aggregate (A4-whole / Arguzz-whole), TESTED trials only
    pool = defaultdict(list)
    for a in atoms:
        if category(a) == "tested":
            pool[a["fuzzer"]].append(a)

    lines = []
    lines.append("# E5 — Full (intrastep, interstep, global) triple distributions (N=250/type)")
    lines.append("")
    lines.append("Distinct-constraint counts per layer, low/high limbs consolidated "
                 "(`MemoryWrite:99`+`:100` = 1, `IsRead:79`+`:80` = 1). "
                 "Global counts distinct families (memory/cycle/register).")
    lines.append("")
    lines.append("All rates/means use the **effective-trials denominator = applied & non-crashed**, "
                 "so neither crashes nor not-applied runs distort them.")
    lines.append("")
    lines.append("**Applied** = the mutation actually ran: Arguzz emits `<fault>` only when the "
                 "injection kind matched the instruction at the step; A4 emits `<a4_config_loaded>`. "
                 "**Not applied** = Arguzz no-op (injection kind didn't match the instruction) OR "
                 "A4 had no valid target transaction at the sampled site (so no config was built — "
                 "A4's applicability limit, the mirror of Arguzz no-ops). These never ran a mutation, "
                 "so they are NOT real `(0,0,0)` outcomes. **Errored/no-constraints-tested** = "
                 "prover error (`PROVE_ERROR`), preflight/other crash, or verify-reject: the prover "
                 "aborted before evaluating constraints, so there is no `(a,b,c)` data.")
    lines.append("")
    lines.append("Metrics per type (and pooled per fuzzer): layer-fire rates, single-constraint "
                 "rate, mean constraints/layer. Then the full triple enumeration.")
    lines.append("")
    lines.append("Bucketing: intrastep `{0, 1, c=≥2}` · interstep `{0, 1}` · global `{0, 1, 2}` (raw).")
    lines.append("")

    # ---- concatenated SUMMARY table (every type-variant, at the top) ----
    lines.append("## SUMMARY — layer-fire rates for every mutation")
    lines.append("")
    lines.append("One row per fuzzer×mutation. Percentages use the **tested-trial denominator** "
                 "(mutation applied AND constraints evaluated; excludes not-applied and "
                 "errored/no-constraint-data). The three layer columns are independent binaries "
                 "(can overlap → a row need not sum to 100%). **none %** = fraction with a genuine "
                 "`(0,0,0)` (zero constraints broken). Low/high limbs are consolidated to one "
                 "constraint throughout.")
    lines.append("")
    lines.append("| fuzzer | mutation | n(tested) | local (intra) % | local (inter) % | global % | none % |")
    lines.append("|---|---|---|---|---|---|---|")
    summary = []
    for fuz in ("arguzz", "a4"):
        m = metrics(pool.get(fuz, []))
        if m:
            summary.append((fuz, "**ALL (pooled)**", m))
    for key in sorted(groups, key=sort_key):
        fuz, mt, var = key
        tested = [a for a in groups[key] if category(a) == "tested"]
        m = metrics(tested)
        if m:
            summary.append((fuz, mt + (f" · {var}" if var else ""), m))
    for fuz, name, m in summary:
        lines.append(f"| {fuz} | {name} | {m['d']} | {m['p_intra']*100:.1f} | "
                     f"{m['p_inter']*100:.1f} | {m['p_glob']*100:.1f} | {m['p_none']*100:.1f} |")
    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## AGGREGATE — by fuzzer (all types pooled, tested trials)")
    lines.append("")
    lines.append("Pooled over every **tested** run (mutation applied AND constraints evaluated) "
                 "of that fuzzer; micro-average, weighted by how often each type is tested. "
                 "Excludes not-applied (no-ops / config errors) and errored/no-constraint-data "
                 "(prove-errors, crashes, verify-rejects).")
    lines.append("")
    for fuz in ("arguzz", "a4"):
        m = metrics(pool.get(fuz, []))
        if not m:
            continue
        lines.append(f"### {fuz} — all mutations")
        lines += render_metrics(m)
    lines.append("---")
    lines.append("")

    for key in sorted(groups, key=sort_key):
        fuz, mt, var = key
        runs = groups[key]
        n = len(runs)
        cats = defaultdict(list)
        for a in runs:
            cats[category(a)].append(a)
        tested = cats["tested"]
        not_applied = cats["not_applied"]
        no_data = cats["no_data"]
        # breakdown of the no-constraint-data bucket by outcome_class
        nd_break = Counter(a.get("outcome_class") for a in no_data)

        title = f"{fuz} · {mt}" + (f" · {var}" if var else "")
        lines.append(f"## {title}")
        lines.append("")
        lines.append(f"- n = **{n}** | not applied = **{len(not_applied)}** "
                     f"({not_applied_reason(fuz)}) | "
                     f"errored/no-constraints-tested = **{len(no_data)}** "
                     f"{dict(nd_break) if no_data else ''} | "
                     f"**tested = {len(tested)}**")
        lines.append("")

        # ---- the three requested metrics, on TESTED trials only ----
        m = metrics(tested)
        if m:
            lines += render_metrics(m)
        # reuse 'fired_nc' name below for the enumeration tables
        fired_nc = tested

        # RAW enumeration over fired, non-crashed
        raw = Counter(distinct_counts(a) for a in fired_nc)
        lines.append("**Raw triples `(intra, inter, global)`** (over tested trials):")
        lines.append("")
        lines.append("| (intra, inter, global) | count |")
        lines.append("|---|---|")
        # sort by count desc, then tuple asc
        for trip, cnt in sorted(raw.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"| ({trip[0]}, {trip[1]}, {trip[2]}) | {cnt} |")
        lines.append("")

        # BUCKETED summary
        buck = Counter()
        for a in fired_nc:
            i, j, g = distinct_counts(a)
            buck[(bucket_intra(i), str(j), str(g))] += 1
        lines.append("**Bucketed `(intra{0,1,c}, inter{0,1}, global{0,1,2})`:**")
        lines.append("")
        lines.append("| (intra, inter, global) | count |")
        lines.append("|---|---|")
        for trip, cnt in sorted(buck.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"| ({trip[0]}, {trip[1]}, {trip[2]}) | {cnt} |")
        lines.append("")

    with open(OUT_MD, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {OUT_MD}")
    print(f"groups: {len(groups)} | atoms: {len(atoms)}")


if __name__ == "__main__":
    main()
