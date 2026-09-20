#!/usr/bin/env python3
"""Per-occurrence detail for the seed-1234 EXCLUSIVE constraint-locations.
RUNS ON COINBASE. For each (job, exclusive-loc): every failures row in the final campaign ->
mutation index (re-indexed 1..N), major, minor, and the mutation's kind. Read-only, in place."""
import subprocess
NODES = "gard goracle idex meld tinyman yieldly algofi stoi pact".split()
SSHO = "-o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=no -o LogLevel=ERROR".split()
NODE_SCRIPT = r'''
import sqlite3, os
SPECS = {
  "g0_baseline_Hybrid_cTS_seed1234": ["ControlMRET@inst_control.zir:93", "ECallHostReadWords@inst_ecall.zir:171"],
  "g3_accelerator_V6_cTS_seed1234": ["ECallTerminate@inst_ecall.zir:46"],
  "g3_accelerator_Hybrid_cTS_seed1234": ["ECallHostReadWords@inst_ecall.zir:171"],
}
for rid, locs in SPECS.items():
    db = f"/tmp/chainjob_pos_iv_pos_9_b_{rid}_n5000/run.db"
    if not os.path.exists(db): continue
    c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    mx = c.execute("select max(id) from campaigns").fetchone()[0]
    start = c.execute("select min(id) from mutations where campaign_id=?", (mx,)).fetchone()[0] or 1
    for loc in locs:
        rows = c.execute("select f.mutation_id, f.major, f.minor, m.kind, m.verifier_accepted "
                         "from failures f join mutations m on f.mutation_id=m.id "
                         "where m.campaign_id=? and f.constraint_loc=? order by f.mutation_id", (mx, loc)).fetchall()
        print(f"LOC|{rid}|{loc}|count={len(rows)}")
        for mid, major, minor, kind, acc in rows:
            print(f"OCC|{rid}|{loc}|idx={mid-start+1}|major={major}|minor={minor}|kind={kind}|verifier_accepted={acc}")
    c.close()
'''
for n in NODES:
    try:
        r = subprocess.run(["ssh", *SSHO, n, "python3", "-"], input=NODE_SCRIPT, capture_output=True, text=True, timeout=60)
        if r.stdout.strip():
            print(r.stdout, end="")
    except Exception:
        pass
