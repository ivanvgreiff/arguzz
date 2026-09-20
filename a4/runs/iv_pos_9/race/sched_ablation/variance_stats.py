#!/usr/bin/env python3
"""Per-seed spread of the ablation find metrics — to (a) choose the right variance metric and
(b) test whether the Hybrid<V0 gap is real. Same DB copies / same find predicate."""
import sys, statistics
sys.path.insert(0, "/root/arguzz")
sys.path.insert(0, "/root/arguzz/a4/runs/iv_pos_9/race/sched_ablation")
import sched_ablation_lib as L

data = L.load_data(L.DEFAULT_RESULTS)


def stat(x):
    m = statistics.mean(x)
    sd = statistics.stdev(x) if len(x) > 1 else 0.0
    sem = sd / (len(x) ** 0.5) if x else 0.0
    cv = 100 * sd / m if m else 0.0
    return m, sd, sem, cv, min(x), max(x)


print(f"N={data['N']}  (per-seed metrics; n = #seeds done)\n")
for v in data["variants"]:
    runs = sorted([r for r in data["per_run"] if r["variant"] == v], key=lambda r: r["seed"])
    finds = [r["n_finds"] for r in runs]
    fd = [100 * r["n_finds"] / r["n_applied"] for r in runs]                                   # find_density %
    pai = [100 * r["n_instr_type_mod_applied"] / r["n_applied"] for r in runs]                 # P(apply ITM) %
    pfi = [100 * r["n_finds"] / r["n_instr_type_mod_applied"] for r in runs if r["n_instr_type_mod_applied"]]  # P(find|ITM) %
    print(f"=== {v}  (n={len(runs)} seeds) ===")
    print("  per-seed finds:", finds)
    for name, x, unit in [("finds/seed", finds, "cnt"), ("find_density", fd, "pp"),
                          ("P(apply ITM)", pai, "pp"), ("P(find|ITM)", pfi, "pp")]:
        m, sd, sem, cv, lo, hi = stat(x)
        u = "" if unit == "cnt" else "%"
        print(f"  {name:13} mean={m:7.3f}{u}  SD={sd:6.3f}{'pp' if unit=='pp' else ''}  "
              f"SEM={sem:6.3f}  CV={cv:5.1f}%  range=[{lo:.2f},{hi:.2f}]")
    print()
