#!/usr/bin/env python3
"""Mean # distinct compressed-global contexts a single APPLIED mutation breaks, per variant.
record_compressed_global_first_hit() is called once per (mutation, distinct ctx_key) and bumps hit_count,
so SUM(hit_count over final campaign) == sum over mutations of (#distinct ctx_keys it broke).
mean = SUM(hit_count) / (#applied mutations in final campaign). RUNS ON COINBASE, read-only, in place."""
import subprocess, glob, os
NODES = "gard goracle idex meld tinyman yieldly algofi stoi pact".split()
SSHO = "-o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=no -o LogLevel=ERROR".split()
CORE = r'''
def stat(c, src, g, v, s):
    if c.execute("pragma quick_check").fetchone()[0] != "ok": return None
    camps=[r[0] for r in c.execute("select id from campaigns order by id")]
    if not camps: return None
    mx=max(camps)
    sh=c.execute("select coalesce(sum(hit_count),0) from compressed_global_coverage where campaign_id=?",(mx,)).fetchone()[0]
    na=c.execute("select count(*) from mutations where outcome='applied' and campaign_id=?",(mx,)).fetchone()[0]
    nc=c.execute("select count(*) from compressed_global_coverage where campaign_id=?",(mx,)).fetchone()[0]
    tg=c.execute("select count(*) from global_failures gg join mutations m on gg.mutation_id=m.id where m.campaign_id=?",(mx,)).fetchone()[0]
    return f"{src}|{g}|{v}|{s}|{sh}|{na}|{nc}|{tg}"
'''
NODE = CORE + r'''
import sqlite3, glob, os, sys
ARG=("V6_uniform","V6_cTS","Hybrid_cTS")
for d in sorted(glob.glob("/tmp/chainjob_pos_iv_pos_9_b_*/")):
    db=d+"run.db"
    if not os.path.exists(db) or not os.path.exists(d+".OK"): continue
    b=os.path.basename(d.rstrip("/")).replace("chainjob_pos_iv_pos_9_b_","").replace("_n5000","")
    v=next((x for x in ARG if f"_{x}_" in b),None)
    if not v: continue
    g=b.split(f"_{v}_")[0]; s=b.split("_seed")[1]
    try:
        c=sqlite3.connect(f"file:{db}?mode=ro",uri=True); o=stat(c,"stepdomain_rerun",g,v,s); c.close()
        if o: print(o)
    except Exception as e: print(f"#ERR {d} {e}",file=sys.stderr)
'''
lines=[]
for n in NODES:
    try: r=subprocess.run(["ssh",*SSHO,n,"python3","-"],input=NODE,capture_output=True,text=True,timeout=120)
    except Exception: continue
    lines+=[l for l in r.stdout.splitlines() if l and not l.startswith("#")]
import sqlite3
exec(CORE)
seen=set()
for db in sorted(glob.glob("/tmp/ivg_sweep/results_rerun/**/run.db",recursive=True)+glob.glob("/tmp/ivg_sweep/results_miss/**/run.db",recursive=True)):
    if "_V5_control_" not in db: continue
    b=os.path.basename(os.path.dirname(db)).replace("pos_iv_pos_9_b_","").replace("_n5000","")
    g=b.split("_V5_control_")[0]; s=b.split("_seed")[1]
    if (g,s) in seen: continue
    try:
        c=sqlite3.connect(f"file:{db}?mode=ro",uri=True); o=stat(c,"3kind_rerun_external",g,"V5_control",s); c.close()
        if o: lines.append(o); seen.add((g,s))
    except Exception: pass
print("source|guest|variant|seed|sum_hit|n_applied|n_ctx|tot_gf")
for l in lines: print(l)
