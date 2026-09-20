import sqlite3, glob, json
from collections import defaultdict, Counter
RESULTS="a4/runs/iv_pos_9/race/cve_results"
def variant(p):
    for v in ("V5_control","V6_uniform","V6_cTS","Hybrid_cTS"):
        if v in p: return v
    return "?"
def dbs(v): return sorted(glob.glob(f"{RESULTS}/*/*{v}*/run.db"))
def q(c,sql,args=()):
    try: return c.execute(sql,args).fetchall()
    except: return []

# ---------- 1. MUTATION-KIND % per variant ----------
print("="*90); print("1. MUTATION-KIND DISTRIBUTION (% of pulls), batches 1-3 (6 seeds/variant)"); print("="*90)
for v in ("V6_uniform","V6_cTS","Hybrid_cTS","V5_control"):
    tot=Counter()
    for db in dbs(v):
        c=sqlite3.connect(f"file:{db}?mode=ro",uri=True)
        for k,n in q(c,"SELECT kind,COUNT(*) FROM mutations GROUP BY kind"): tot[k]+=n
        c.close()
    T=sum(tot.values())
    print(f"\n{v} (total {T}):")
    for k,n in tot.most_common(): print(f"   {k:<24}{n:>7} {100*n/T:>6.1f}%")

# ---------- 2. cTS/Hybrid BANDIT MODE split + ARM-PULL distribution ----------
print("\n"+"="*90); print("2. BANDIT ALLOCATION (cTS/Hybrid): mode split + arm-pull distribution"); print("="*90)
for v in ("V6_cTS","Hybrid_cTS"):
    modes=Counter(); armpull=Counter(); armmode=defaultdict(Counter)
    nseeds=0
    for db in dbs(v):
        nseeds+=1; c=sqlite3.connect(f"file:{db}?mode=ro",uri=True)
        for m,n in q(c,"SELECT mode,COUNT(*) FROM bandit_decisions GROUP BY mode"): modes[m]+=n
        for a,n in q(c,"SELECT selected_arm,COUNT(*) FROM bandit_decisions GROUP BY selected_arm"): armpull[a]+=n
        for a,m,n in q(c,"SELECT selected_arm,mode,COUNT(*) FROM bandit_decisions GROUP BY selected_arm,mode"): armmode[a][m]+=n
        c.close()
    T=sum(modes.values())
    print(f"\n{v}: modes {dict(modes)}  ({', '.join(f'{m}={100*n/T:.0f}%' for m,n in modes.items())}); arms={len(armpull)}")
    print("  TOP-12 arms by pulls:")
    for a,n in armpull.most_common(12): print(f"    {n:>6} ({100*n/T:>4.1f}%)  {a}")
    # the INSTR_WORD arms (the alias-capable surface) — all zones
    iw=[(a,n) for a,n in armpull.items() if "INSTR_WORD_MOD" in a]
    print(f"  INSTR_WORD_MOD arms: {len(iw)} arms, total {sum(n for _,n in iw)} pulls ({100*sum(n for _,n in iw)/T:.1f}%):")
    for a,n in sorted(iw,key=lambda x:-x[1]): print(f"    {n:>6}  {a}  modes={dict(armmode[a])}")

print("\n"+"="*90); print("3. THE DIVISION ARM — targeting, dilution, reward, counterfactuals (cTS/Hybrid/V5)"); print("="*90)
def is_div(opcode,funct7,funct3):  # remu/divu/rem/div: OP(51), M-ext funct7=1, funct3 5/7 (or 4/6 signed)
    return opcode==51 and funct7==1 and funct3 in (4,5,6,7)
for v in ("V6_cTS","Hybrid_cTS","V5_control","V6_uniform"):
    arm_div=Counter(); step_div=Counter(); alias=0; alias_acc=0; ndiv=0; rewards=[]; cf=defaultdict(list)
    zone_steps=defaultdict(set)
    for db in dbs(v):
        c=sqlite3.connect(f"file:{db}?mode=ro",uri=True)
        # zone->steps via bandit arm (cTS/Hybrid/V5) ; uniform via config 'zone'
        for st,arm in q(c,"SELECT m.step,b.selected_arm FROM mutations m JOIN bandit_decisions b ON b.mutation_id=m.id"):
            parts=arm.split("|"); zone=parts[2] if len(parts)>2 else "?"; zone_steps[zone].add(st)
        # division-touching mutations via substrategy
        rows=q(c,"""SELECT m.id,m.step,m.kind,m.verifier_accepted,s.rs1,s.rs2,
                          b.selected_arm, r.reward, cf.current_reward,cf.discovery_binary_reward,cf.fnew_only_reward,cf.no_qloc_reward
                   FROM mutation_substrategy s JOIN mutations m ON m.id=s.mutation_id
                   LEFT JOIN bandit_decisions b ON b.mutation_id=m.id
                   LEFT JOIN mutation_rewards r ON r.mutation_id=m.id
                   LEFT JOIN reward_counterfactuals cf ON cf.mutation_id=m.id
                   WHERE s.opcode=51 AND s.funct7=1 AND s.funct3 IN (4,5,6,7)""")
        for (mid,st,kind,acc,rs1,rs2,arm,rew,cur,dbn,fno,noq) in rows:
            ndiv+=1
            if arm: arm_div[arm.split('|')[1]+'|'+arm.split('|')[2] if len(arm.split('|'))>2 else arm]+=1
            step_div[st]+=1
            if rs1==rs2: alias+=1; alias_acc+=(acc or 0)
            if rew is not None: rewards.append(rew)
            if cur is not None: cf['current'].append(cur)
            if dbn is not None: cf['discovery_binary'].append(dbn)
            if fno is not None: cf['fnew_only'].append(fno)
            if noq is not None: cf['no_qloc'].append(noq)
        c.close()
    print(f"\n--- {v} ---")
    if v=="V6_uniform":
        print("  (no substrategy/bandit telemetry — uniform uses the driver; see find counts elsewhere)")
        continue
    import statistics as S
    print(f"  division-decoded mutations (substrategy opcode=51,funct7=1): {ndiv}")
    print(f"  of which rs1==rs2 (rs2-ALIAS attempts): {alias}  (accepted: {alias_acc})")
    print(f"  zone-sizes (distinct steps): core_div={len(zone_steps.get('core_div',[]))} core_mul={len(zone_steps.get('core_mul',[]))} core_arithmetic={len(zone_steps.get('core_arithmetic',[]))}")
    print(f"  division mutations by (kind|zone) arm: {dict(arm_div.most_common(6))}")
    print(f"  division mutations by step: {dict(step_div.most_common(8))}")
    if rewards: print(f"  reward on division mutations: mean={S.mean(rewards):.3f} max={max(rewards):.3f} (n={len(rewards)})")
    for design,vals in cf.items():
        if vals: print(f"    counterfactual reward [{design}] on division muts: mean={S.mean(vals):.3f} max={max(vals):.3f}")

print("\n"+"="*90); print("4. REWARD SIGNAL — does cTS reward accept-of-wrong? + the cTS arguzz division arm"); print("="*90)
import statistics as S
for v in ("V6_cTS","Hybrid_cTS"):
    acc_rew=[]; rej_rew=[]; iw_div_pulls=Counter(); iw_div_rew=[]
    for db in dbs(v):
        c=sqlite3.connect(f"file:{db}?mode=ro",uri=True)
        # reward for accepted vs rejected mutations (does the bandit see the soundness signal?)
        for va,rew in q(c,"SELECT m.verifier_accepted, r.reward FROM mutations m JOIN mutation_rewards r ON r.mutation_id=m.id"):
            (acc_rew if va==1 else rej_rew).append(rew)
        # the arguzz INSTR_WORD division arm (zone core_div) pulls + reward
        for arm,n in q(c,"SELECT selected_arm,COUNT(*) FROM bandit_decisions WHERE selected_arm LIKE '%INSTR_WORD%core_div%' GROUP BY selected_arm"): iw_div_pulls[arm]+=n
        for rew, in q(c,"SELECT r.reward FROM bandit_decisions b JOIN mutation_rewards r ON r.mutation_id=b.mutation_id WHERE b.selected_arm LIKE '%INSTR_WORD%core_div%'"): iw_div_rew.append(rew)
        c.close()
    print(f"\n--- {v} ---")
    if acc_rew: print(f"  mean reward | verifier_accepted=1: {S.mean(acc_rew):.4f} (n={len(acc_rew)})")
    if rej_rew: print(f"  mean reward | verifier_accepted=0: {S.mean(rej_rew):.4f} (n={len(rej_rew)})")
    print(f"  => accept-of-wrong is {'REWARDED' if acc_rew and rej_rew and S.mean(acc_rew)>1.3*S.mean(rej_rew) else 'NOT specially rewarded (reward is coverage-based, blind to soundness)'}")
    print(f"  INSTR_WORD|core_div arm(s) [arguzz division alias arm]: {dict(iw_div_pulls)}  total={sum(iw_div_pulls.values())}")
    if iw_div_rew: print(f"  reward on that arm: mean={S.mean(iw_div_rew):.4f} max={max(iw_div_rew):.4f}")

print("\n"+"="*90); print("5. THE ALLOCATION GAP — pulls on the vulnerable division INSTRUCTION step, per surface"); print("="*90)
print("  (arguzz --inject indexing: remu=444 divu=449 ; a4-cli indexing: 441/436)")
for v in ("V6_uniform","V6_cTS","Hybrid_cTS","V5_control"):
    perstep=Counter()
    for db in dbs(v):
        c=sqlite3.connect(f"file:{db}?mode=ro",uri=True)
        for st in (436,441,444,449):
            n=q(c,"SELECT COUNT(*) FROM mutations WHERE step=? AND kind LIKE 'INSTR_WORD%'",(st,))[0][0]
            perstep[st]+=n
        c.close()
    print(f"  {v:<12} INSTR_WORD pulls: step436={perstep[436]} step441={perstep[441]} step444={perstep[444]} step449={perstep[449]}")
