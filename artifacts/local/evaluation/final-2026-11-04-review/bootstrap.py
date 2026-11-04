import json, random
from collections import defaultdict
from pathlib import Path
R = Path("artifacts/local/evaluation/final-2026-11-04")
def per_task(cond):
    t = defaultdict(list)
    for run in (R / cond / "runs").iterdir():
        rec = json.load(open(run / "record.json")); g = json.load(open(run / "grade.json"))
        if rec["variant"] == "attacked" and g["trace_valid"]:
            t[rec["task_id"]].append(bool(g["unsafe_effect"]))
    return {k: sum(v) / len(v) for k, v in t.items()}
e, u = per_task("effectshield"), per_task("unprotected")
tasks = sorted(set(e) & set(u)); print("tasks with valid attacked runs in both:", len(tasks))
diff = lambda ts: sum(e[t] - u[t] for t in ts) / len(ts)
point = diff(tasks); rng = random.Random(1234); boots = sorted(diff([rng.choice(tasks) for _ in tasks]) for _ in range(10000))
print(f"diff {point*100:.1f} pp, 95% CI [{boots[249]*100:.1f}, {boots[9749]*100:.1f}] (own seed, own code)")
