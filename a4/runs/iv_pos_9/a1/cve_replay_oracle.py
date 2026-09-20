import sys, json, re, argparse, os
from multiprocessing import Pool
sys.path.insert(0,"/root/arguzz")
from a4.standalone.arguzz_invoke import run
BIN="/root/arguzz/workspace/output-a1vuln/target/release/risc0-host"
ARGS=["--ctrl","7","--gseed","12345","--rounds","5"]
CLASS={"9000027":"benign","0":"remu_alias_CVE","9000028":"divu_alias_CVE","1":"both_alias_CVE"}
def replay(r):
    try:
        res=run(BIN, ARGS, int(r["step"]), "INSTR_WORD_MOD", int(r["iter_seed"]), timeout=300)
        m=re.search(r'"context"\s*:\s*"Receipt Decoder"[^}]*"output"\s*:\s*"?(-?\d+)', res.raw_stdout or "")
        outv=m.group(1) if m else None; ps=res.prover_status
    except Exception as e:
        outv=None; ps="err:"+type(e).__name__
    cls = "noparse" if outv is None else CLASS.get(outv,"other_accept_of_wrong")
    return {**r,"output":outv,"prover_status":ps,"cls":cls}
if __name__=="__main__":
    ap=argparse.ArgumentParser(); ap.add_argument("--filter",default="arithmetic"); ap.add_argument("--workers",type=int,default=2); ap.add_argument("--out",required=True)
    a=ap.parse_args()
    wl=json.load(open("/root/arguzz/a4/runs/iv_pos_9/a1/cve_iw_accepts.json"))
    if a.filter=="arithmetic": wl=[r for r in wl if r["opcode_class"]=="arithmetic"]
    elif a.filter=="nonarith": wl=[r for r in wl if r["opcode_class"]!="arithmetic"]
    print(f"replaying {len(wl)} accepts ({a.filter}) workers={a.workers}", flush=True)
    done=[]
    with Pool(a.workers) as p:
        for i,res in enumerate(p.imap_unordered(replay, wl),1):
            done.append(res)
            if i%5==0 or i==len(wl):
                json.dump(done, open(a.out,"w"))
                print(f"  {i}/{len(wl)} done (last: {res['variant']} out={res['output']} {res['cls']})", flush=True)
    from collections import defaultdict
    agg=defaultdict(lambda: defaultdict(int))
    for r in done: agg[r["variant"]][r["cls"]]+=1
    print(f"\n{'variant':<12}{'benign':>8}{'remu_CVE':>9}{'divu_CVE':>9}{'both_CVE':>9}{'other_AoW':>10}{'noparse':>8}")
    for v in ("V5_control","V6_uniform","V6_cTS","Hybrid_cTS"):
        x=agg[v]
        if x: print(f"{v:<12}{x['benign']:>8}{x['remu_alias_CVE']:>9}{x['divu_alias_CVE']:>9}{x['both_alias_CVE']:>9}{x['other_accept_of_wrong']:>10}{x['noparse']:>8}")
