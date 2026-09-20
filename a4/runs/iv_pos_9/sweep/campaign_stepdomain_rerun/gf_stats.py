#!/usr/bin/env python3
"""Per-mutation GLOBAL-failure-count distribution (final campaign), per job.
RUNS ON COINBASE. For each applied mutation we count its rows in global_failures, then bucket:
  0 failures | 1-10 | >10 . This tests the "zero-or-many" (bimodal) claim per variant.
Emits one CSV line per job: source|guest|variant|seed|n_applied|n0|n1_10|ngt10  -> STDOUT.
Reads sources READ-ONLY in place (same two sources as extract_curves.py)."""
import subprocess, sys, glob, os
NODES = "gard goracle idex meld tinyman yieldly algofi stoi pact".split()
SSHO = "-o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=no -o LogLevel=ERROR".split()
CORE = r'''
def stat(c, src, guest, variant, seed):
    if c.execute("pragma quick_check").fetchone()[0] != "ok": return None
    camps = [r[0] for r in c.execute("select id from campaigns order by id")]
    if not camps: return None
    mx = max(camps)
    rows = c.execute(
        "select coalesce(g.cnt,0) from mutations m "
        "left join (select mutation_id, count(*) cnt from global_failures group by mutation_id) g "
        "on g.mutation_id=m.id where m.outcome='applied' and m.campaign_id=?", (mx,)).fetchall()
    cnts = [r[0] for r in rows]
    n = len(cnts)
    if not n: return None
    n0 = sum(1 for x in cnts if x == 0)
    ngt = sum(1 for x in cnts if x > 10)
    return f"{src}|{guest}|{variant}|{seed}|{n}|{n0}|{n-n0-ngt}|{ngt}"
'''
NODE_SCRIPT = CORE + r'''
import sqlite3, glob, os, sys
ARGUZZ = ("V6_uniform","V6_cTS","Hybrid_cTS")
for d in sorted(glob.glob("/tmp/chainjob_pos_iv_pos_9_b_*/")):
    db=d+"run.db"
    if not os.path.exists(db) or not os.path.exists(d+".OK"): continue
    base=os.path.basename(d.rstrip("/")).replace("chainjob_pos_iv_pos_9_b_","").replace("_n5000","")
    v=next((x for x in ARGUZZ if f"_{x}_" in base),None)
    if not v: continue
    g=base.split(f"_{v}_")[0]; s=base.split("_seed")[1]
    try:
        c=sqlite3.connect(f"file:{db}?mode=ro",uri=True); out=stat(c,"stepdomain_rerun",g,v,s); c.close()
        if out: print(out)
    except Exception as e: print(f"#ERR {d} {e}", file=sys.stderr)
'''
lines=[]
for n in NODES:
    try: r=subprocess.run(["ssh",*SSHO,n,"python3","-"],input=NODE_SCRIPT,capture_output=True,text=True,timeout=180)
    except Exception as e: print(f"#node {n} FAIL {e}",file=sys.stderr); continue
    lines+= [l for l in r.stdout.splitlines() if l and not l.startswith("#")]
    print(f"#node {n} ok",file=sys.stderr)
import sqlite3
exec(CORE)
seen=set()
for db in sorted(glob.glob("/tmp/ivg_sweep/results_rerun/**/run.db",recursive=True)+glob.glob("/tmp/ivg_sweep/results_miss/**/run.db",recursive=True)):
    if "_V5_control_" not in db: continue
    base=os.path.basename(os.path.dirname(db)).replace("pos_iv_pos_9_b_","").replace("_n5000","")
    g=base.split("_V5_control_")[0]; s=base.split("_seed")[1]
    if (g,s) in seen: continue
    try:
        c=sqlite3.connect(f"file:{db}?mode=ro",uri=True); out=stat(c,"3kind_rerun_external",g,"V5_control",s); c.close()
        if out: lines.append(out); seen.add((g,s))
    except Exception as e: print(f"#ERR ext {db} {e}",file=sys.stderr)
print("source|guest|variant|seed|n_applied|n0|n1_10|ngt10")
for l in lines: print(l)
print(f"#TOTAL {len(lines)} jobs",file=sys.stderr)
