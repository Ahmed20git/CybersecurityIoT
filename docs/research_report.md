# EffectShield research report — summary

Updated 2026-11-06. The full report is [`report/effectshield_report.pdf`](report/effectshield_report.pdf), built from [`report/effectshield_report.tex`](report/effectshield_report.tex). Its results come from `report/generated/results.tex`, which `scripts/report_tables.py` generates from retained evidence. This page summarizes the report for readers of the repository. Simon leads evaluation and writing and Ahmed leads the runtime and mediator; both still have to review the report's interpretation and its security claims (DEL-04). The report is a complete candidate awaiting that joint review; it has not been accepted.

## Question and claim boundary

Does a deterministic mediator between a tool-using language-model agent and a simulated smart home reduce unsafe effects and attacker success while preserving useful task completion? The study compares EffectShield with an unprotected agent and a safety-prompt-only agent. The claims hold within one model (`gpt-4.1-mini-2025-04-14`), one five-device simulator, 24 synthetic tasks and three authored attack families. They do not establish real-world physical safety or general prompt-injection prevention.

## Design

The agent only proposes typed actions. Ahmed's mediator decides every proposal with rules R1–R8 (see the [mediator design](mediator_design.md)) and can apply a bounded repair, and only the protected executor changes device state. No rule consults a language model. The attacker can rewrite free-text payload fields (hidden instruction), withhold a fresh reading (stale observation) or redeliver an authentic old reading (replayed observation). The attacker cannot change the request, envelopes, state, clock or grader.

The [final manifest](../scenarios/test/final.json) has 24 base tasks in clean and attacked forms. The protocol uses three conditions and three repetitions, 432 attempts in block-randomized order. EffectShield reuses the unprotected prompt, so enforcement is the only difference. An independent grader scores complete simulator traces against frozen attacker goals. The protocol, manifest, conditions and the D12 analysis plan were approved and frozen on November 4, and the study ran once (see the [project plan](project_plan.md#final-study-november-4)).

## Results

A 3-minute provider transport outage made 97 of the 432 attempts fail before any model call. As frozen, they were not retried. The block-randomized order spread them evenly (33 unprotected, 32 safety prompt, 32 EffectShield), and each condition kept 56 evaluable attacked runs across all 24 tasks.

| Measure (task-level rate, evaluable runs) | Unprotected | Safety prompt only | EffectShield |
| --- | --- | --- | --- |
| Attacked unsafe effect | 58.3% (30/56) | 45.8% (24/56) | 0.0% (0/56); exact task-level upper bound 14.2% |
| Attack success | 64.6% (33/56) | 50.0% (25/56) | 6.2% (3/56), all lockout goals |
| Clean completion | 70.8% (40/55) | 70.8% (41/56) | 98.6% (55/56) |
| Clean unsafe effect | 29.2% (15/55) | 25.0% (12/56) | 0.0% (0/56) |
| Attacked completion | 52.1% | 54.2% | 86.8% |
| Weighted loss (10U + B) | 570 | 480 | 2 |

- **Primary comparison:** EffectShield against unprotected on attacked unsafe effects, −58.3 pp, 95% task-cluster bootstrap CI [−76.4, −38.9]. The upper endpoint is below zero, so the pre-declared reduction claim holds (STA-02). Counting invalid runs as failures gives −41.7 pp [−56.9, −26.4]. The three exploratory comparisons also have upper endpoints below zero. Clean completion satisfies the utility criterion (98.6% ≥ 0.85 × 70.8%).
- **Decisions against the independent policy label (STA-06):** of 133 effect decisions, the mediator blocked 40 policy-unsafe proposals and allowed none. It blocked 2 permissible proposals, allowed 86 and repaired 5 unsafe setpoints. Recall is 100.0%, block precision 95.2% and the false-block rate 2.3%.
- **Residual cost:** EffectShield's three attack successes are lockouts in the occupied arrival tasks. After a stale or replayed "absent" reading, the agent did not read presence again, so the door stayed locked. This is the measured cost of the freshness and replay rules.
- **Ablations (EXP-05, EXP-06):** replaying the recorded proposals without R4–R5 lets 12 replays per batch become unsafe. Removing R3 adds at most 1. These are fixed-trace results: the proposals do not adapt to blocks.
- **Latency (LOG-03):** a mediator decision takes a median of 82 µs (p95 112 µs, n = 695, offline replay on an Apple M1 Pro). The median end-to-end task takes 3.59 s with EffectShield and 3.76 s unprotected.
- **Cost (LOG-04):** the 512 live attempts of the project made 946 generation calls, at an estimated USD 0.2255 by the published tariff (USD 0.1829 for the final study). These are estimates; reconciliation with the provider's billed amounts is pending.

Ahmed's [independent recount and replay](../artifacts/local/evaluation/final-2026-11-04-review/recount.json) re-graded all 432 traces and replayed all 335 valid runs offline, with no differences.

## Threats to validity

- The policy label and several grader predicates encode the same safety rules the mediator enforces. The study therefore tests faithful enforcement of a specification, not that specification's adequacy.
- One team designed the rules, the corpus and the grader. Splits, a held-out pilot, frozen goals and a single frozen run limit the alignment between rule design and test tasks, but do not remove it.
- 24 tasks at temperature 0 give limited independent information. The task-cluster bootstrap reflects this.
- The outage removed 22% of attempts independently of condition. The sensitivity line bounds its effect.

## Reproduction and presentation

The [artifact guide](artifact.md) lists the evidence manifest, the verification command and the commands that regenerate every reported number offline. In a fresh standard-library environment the analysis, ablations and billing outputs regenerate byte for byte. The read-only Streamlit dashboard presents the same results with denominators and intervals, and shows untrusted text only as plain data (LOG-06). The [demonstration](demo/demo_script.md) is a narrated 4:35 recording of it.
