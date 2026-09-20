#!/usr/bin/env python3
"""Print the scheduler-ablation per-variant bug-race stats (same metrics as the published race,
new fixed-binary data). Run: python3 a4/runs/iv_pos_9/race/sched_ablation/print_stats.py"""
import sys
sys.path.insert(0, "/root/arguzz")
sys.path.insert(0, "/root/arguzz/a4/runs/iv_pos_9/race/sched_ablation")
import sched_ablation_lib as L

data = L.load_data(L.DEFAULT_RESULTS)
print(f"results_dir = {data['results_dir']}")
print(f"N = {data['N']}   seeds = {data['seeds']}   variants_present = {data['variants']}")
print(f"per-seed counts: " + ", ".join(f"{v}={sum(1 for r in data['per_run'] if r['variant']==v)}" for v in data['variants']))
print()
hdr = f"{'variant':18} {'seeds':5} {'P(found)':9} {'finds':6} {'mean/seed':9} {'P(applyITM)':11} {'cond_find_dens':14} {'find_dens':9} {'per_mut_s':9}"
print(hdr); print("-" * len(hdr))
for r in L.per_variant_table(data):
    pf = f"{r['P_found']:.2f}" if r['P_found'] is not None else "NA"
    cfd = f"{r['cond_find_density']:.4f}" if r['cond_find_density'] is not None else "NA"
    print(f"{r['variant']:18} {r['seeds_done']:5} {pf:9} {r['total_finds']:6} {r['mean_finds']:9.1f} "
          f"{r['p_apply_itm']:11.3f} {cfd:14} {r['find_density']:9.4f} {r['mean_per_mut_s']:9.2f}")
print()
print("KEY: P(applyITM)=ITM-applied/total-applied (scheduler-attributable);"
      " cond_find_dens=finds/ITM-applied (bug-intrinsic); find_dens=finds/applied.")
print("Ladder: V8 (no arms,no bandit) -> V0 (arms,no bandit) -> V5 (arms+bandit); Hybrid = surface mix.")
