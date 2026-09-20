#!/usr/bin/env python3
"""Coverage extractor for the IV.POS.9 step-domain re-run campaign.

RUNS ON COINBASE. Reads two sources, both READ-ONLY and IN PLACE (never moved, never edited):
  A. this campaign  (V6_uniform, V6_cTS, Hybrid_cTS): /tmp/chainjob_*/run.db on each POS node (ssh node python3 -)
  B. external V5_control (A4): coinbase results_rerun/{b1,b2,b3} + results_miss/b1 (3-kind re-run; A4 immune).

FINAL-CAMPAIGN ONLY (restart de-contamination, see PROVENANCE.md): only the last campaign (max campaign_id =
the clean 5000-run) is read; ids are re-indexed to 1..N. `ncamp` records restart count.

Emits THREE | -delimited CSV blocks to STDOUT, separated by `###JOBS` / `###CURVES` / ###KEYS`:
  JOBS   : one row per job (provenance + final counts + ncamp)
  CURVES : first-hit mutation ids per (job, metric) -> coverage trajectories
  KEYS   : the actual distinct context keys per (job, metric) -> for territory/exclusivity set-algebra
           (LOC=constraint_loc, CTX=constraint_loc|major|minor, CGC=ctx_key). Key is the LAST field and may
           itself contain '|' -> parse with maxsplit. Diagnostics -> STDERR.
"""
import subprocess, sys, glob, sqlite3, os

NODES = "gard goracle idex meld tinyman yieldly algofi stoi pact".split()
SSHO = "-o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=no -o LogLevel=ERROR".split()

# Shared per-DB extraction (used identically on nodes and on coinbase). Emits J/C/K lines for src/guest/variant/seed.
CORE = r'''
def emit(c, src, guest, variant, seed, host, db):
    if c.execute("pragma quick_check").fetchone()[0] != "ok":
        return False
    camps = [r[0] for r in c.execute("select id from campaigns order by id")]
    if not camps:
        return False
    mx = max(camps); nc = len(camps)
    start = c.execute("select min(id) from mutations where campaign_id=?", (mx,)).fetchone()[0] or 1
    fmut = c.execute("select count(*) from mutations where campaign_id=?", (mx,)).fetchone()[0]
    rows = {
        "LOC": c.execute("select f.constraint_loc, min(f.mutation_id) from failures f join mutations m on f.mutation_id=m.id where m.campaign_id=? group by f.constraint_loc", (mx,)).fetchall(),
        "CTX": c.execute("select f.constraint_loc||'|'||f.major||'|'||f.minor, min(f.mutation_id) from failures f join mutations m on f.mutation_id=m.id where m.campaign_id=? group by f.constraint_loc,f.major,f.minor", (mx,)).fetchall(),
        "CGC": c.execute("select ctx_key, first_hit_mutation_id from compressed_global_coverage where campaign_id=?", (mx,)).fetchall(),
    }
    n = {k: len(v) for k, v in rows.items()}
    print(f"J|{src}|{guest}|{variant}|{seed}|{host}|{db}|{fmut}|{nc}|{n['LOC']}|{n['CTX']}|{n['CGC']}")
    for metric, rs in rows.items():
        for key, mid in rs:
            if key is None:
                continue
            if mid is not None:
                print(f"C|{src}|{guest}|{variant}|{seed}|{host}|{metric}|{mid-start+1}")
            print(f"K|{src}|{guest}|{variant}|{seed}|{metric}|{key}")
    return True
'''

NODE_SCRIPT = CORE + r'''
import sqlite3, glob, os, socket, sys
NODE = socket.gethostname()
ARGUZZ = ("V6_uniform", "V6_cTS", "Hybrid_cTS")
for d in sorted(glob.glob("/tmp/chainjob_pos_iv_pos_9_b_*/")):
    db = d + "run.db"
    if not os.path.exists(db) or not os.path.exists(d + ".OK"):
        continue
    base = os.path.basename(d.rstrip("/")).replace("chainjob_pos_iv_pos_9_b_", "").replace("_n5000", "")
    variant = next((v for v in ARGUZZ if f"_{v}_" in base), None)
    if not variant:
        continue
    guest = base.split(f"_{variant}_")[0]; seed = base.split("_seed")[1]
    try:
        c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        emit(c, "stepdomain_rerun", guest, variant, seed, NODE, db)
        c.close()
    except Exception as e:
        print(f"#ERR {NODE} {d} {e}", file=sys.stderr)
'''

out_lines = []
# ---- A. this campaign (nodes) ----
for n in NODES:
    try:
        r = subprocess.run(["ssh", *SSHO, n, "python3", "-"], input=NODE_SCRIPT,
                           capture_output=True, text=True, timeout=180)
    except Exception as e:
        print(f"#node {n} FAIL {e}", file=sys.stderr); continue
    nj = sum(1 for ln in r.stdout.splitlines() if ln.startswith("J|"))
    out_lines.extend(r.stdout.splitlines())
    if r.stderr.strip():
        print(r.stderr.strip(), file=sys.stderr)
    print(f"#node {n}: {nj} completed jobs", file=sys.stderr)

# ---- B. external V5_control (coinbase, read-only) ----
exec(CORE)
seen = set(); n_ext = 0
ext_dbs = sorted(glob.glob("/tmp/ivg_sweep/results_rerun/**/run.db", recursive=True) +
                 glob.glob("/tmp/ivg_sweep/results_miss/**/run.db", recursive=True))
import io, contextlib
for db in ext_dbs:
    if "_V5_control_" not in db:
        continue
    base = os.path.basename(os.path.dirname(db)).replace("pos_iv_pos_9_b_", "").replace("_n5000", "")
    guest = base.split("_V5_control_")[0]; seed = base.split("_seed")[1]
    if (guest, seed) in seen:
        continue
    try:
        c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ok = emit(c, "3kind_rerun_external", guest, "V5_control", seed, "coinbase", db)
        c.close()
        if ok:
            out_lines.extend(buf.getvalue().splitlines()); seen.add((guest, seed)); n_ext += 1
    except Exception as e:
        print(f"#ERR ext {db} {e}", file=sys.stderr)
print(f"#external V5_control: {n_ext} jobs", file=sys.stderr)

jobs = [l for l in out_lines if l.startswith("J|")]
curves = [l for l in out_lines if l.startswith("C|")]
keys = [l for l in out_lines if l.startswith("K|")]

print("###JOBS")
print("kind|source|guest|variant|seed|host|db_path|n_mut|ncamp|final_loc|final_ctx|final_cgc")
for j in jobs: print(j)
print("###CURVES")
print("kind|source|guest|variant|seed|host|metric|first_hit_mutation_id")
for c in curves: print(c)
print("###KEYS")
print("kind|source|guest|variant|seed|metric|key")
for k in keys: print(k)
print(f"#TOTAL jobs={len(jobs)} curves={len(curves)} keys={len(keys)}", file=sys.stderr)
