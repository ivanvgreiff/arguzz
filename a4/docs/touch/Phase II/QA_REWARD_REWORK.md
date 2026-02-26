# Q&A: Reward Rework (Phase II.2R)

---

## Q1: Does using direct assignment instead of max() in seed_from_baseline contradict Pro_Report_6/7?

No. Neither Pro_Report_6 nor Pro_Report_7 specifies the exact implementation of baseline seeding at the assignment level. 

Pro_Report_6 §4 says: "Initialize `state.global_bitmap` and `state.freq` by merging the baseline bitmap and setting `freq[i]+=1` for touched indices."

Pro_Report_7 Q3 says: "set `seen_touch[i]=1` for all baseline-touched (i), set `freq_touch[i]=1` for those (i)."

Neither says "use max" or "use direct assignment." Both describe the same outcome: after seeding, baseline-touched buckets have their bitmap values set and freq=1. The max() was my own defensive design choice in the implementation plan (not from ChatGPT), and I changed it to direct assignment after your question because it's simpler and the state is guaranteed to be zeroed when seed_from_baseline is called (it's called immediately after CoverageState creation, before any runs). The functional result is identical.

---

## Q2: How does novelty decay if we no longer have a rolling window?

The rolling window was used for the **saturation switch** in the original reward: when median(Δ_T in last W runs) < 1, switch from S_new to S_rare. Pro_Report_6 §6 item 4 explicitly says: "Remove or de-emphasize the rolling-window median saturation switch."

In the revised reward, there is **no switch** between novelty and rarity modes. Both T_new and T_rare (and F_new and F_rare) are **always computed** and combined via the weighted average:

```
S = (a_Tn * T_new + a_Tr * T_rare + a_Fn * F_new + a_Fr * F_rare + a_Z * Z) / total_weight
```

Novelty "decays" naturally:
- **T_new** starts high (many new bitmap buckets on early runs) and drops to 0 as the global bitmap fills up. It doesn't need a window to "detect" saturation — it simply returns 0 when delta_T = 0.
- **F_new** similarly starts high and decays as more failure context_ids are seen. But it decays more slowly than T_new (31% of runs still have nonzero delta_F after 200 runs, vs 8% for delta_T).
- **T_rare and F_rare** don't decay — they remain informative because they measure rarity (how frequently each bucket/context was seen across the campaign), which changes with every run.

So the weighted average naturally transitions from "novelty-dominated" (early in campaign when T_new and F_new are high) to "rarity-dominated" (later when T_new≈0 and F_new approaches 0, but T_rare and F_rare still vary). No explicit switch needed.

This is cleaner than the original saturation switch because:
1. The switch was binary (novelty OR rarity) — the weighted average is continuous
2. The switch happened too early (after ~2 runs) because of the 1599→0 touch cliff
3. The switch was based only on touch novelty, ignoring failure novelty entirely
