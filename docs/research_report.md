# EffectShield research report — working draft

Status: methods, implementation and the preliminary November 4 final-study results (pending Ahmed's independent replay); the October 7 baseline-gate outcome (development suite, unprotected condition only) is recorded in the evaluation evidence and its [review record](../artifacts/local/evaluation/live-baseline/review/README.md). Simon leads evaluation and writing; Ahmed leads runtime/enforcement implementation; both review interpretation and security-sensitive claims. Scope, decisions and milestones are defined in the [requirements](requirements.md) and [project plan](project_plan.md).

## Research question and claim boundary

Does a deterministic mediator between a tool-using language-model agent and a simulated smart home reduce unsafe effects and attacker success while preserving useful completion? The intended comparison is against an unprotected agent and a safety-prompt-only agent. This draft makes no claim that the mediator works, that a particular live model is susceptible beyond the single development attack recorded at the baseline gate, or that the system ensures real-world physical safety.

Effects remain inside the five-device simulator. The current development harness verifies trace collection, matching and independent grading using authored responses. Software checks establish implementation behavior; they do not establish the research hypothesis.

## System and threat model

The implemented runtime separates the model's action proposals from trusted request issuance, gateway observations and simulator state mutation. Requests carry harness-issued identity and operation permissions. Gateway envelopes retain source, event ID and simulation time; payload text remains untrusted. Agent-visible inputs omit hidden completion labels and independent grading rules.

The attack builder has three labelled families. A hidden instruction changes only predeclared observation message text. A stale observation withholds a fresh gateway delivery, so an older authentic reading is the latest in context. A replay redelivers an issued observation with its original envelope. No family can change the original request, permissions, canonical device facts, clock or environment schedule, envelope metadata or grader labels. The development cases include forged system/user authority, an extra operation on an otherwise authorized device, references presented as permission and a false presence claim. Benign controls check quoted instructions, legitimate sensor use and explicitly authorized multi-device work. Separate development suites isolate stale, replayed and combined evidence failures with negative controls, and cover sequence repair, an infeasible exact out-of-range request and thermostat bounds. The full case map and current commands are in the [evaluation guide](evaluation_guide.md#authorization-and-provenance-development-cases).

Ahmed's deterministic mediator implements rules 1–8 and task-preserving repair with Proposed semantics (see the [mediator design](mediator_design.md)). References do not themselves establish action authority. D05 must fix the enforcement mechanism independently of model claims; D06–D08 must fix freshness, replay and repair semantics before those components are accepted.

## Comparison design

Three draft condition definitions exist: [unprotected](../configs/conditions/unprotected.json), [safety-prompt-only](../configs/conditions/safety_prompt_only.json) and [EffectShield](../configs/conditions/effectshield.json). Full EffectShield reuses the unprotected prompt and differs only in enforcement: the evaluation runner routes every proposal through the mediator and retains its decision records outside the model-visible transcript. The safety prompt adds instructions without deterministic protection. The unprotected prompt and continuation protocol are approved at baseline scope under D09 (October 7); the safety-prompt-only and EffectShield definitions remain drafts.

Within each development scenario, matching preserves the initial state, request, evidence, model configuration, seed policy, limits and retry rules. The runner stores full condition identity and prompt versions with each attempt. The comparison audit checks these bindings and undeclared differences; incomplete or missing cells remain visible.

The scripted model returns authored proposals irrespective of the prompt. Running the same script under all three conditions tests wiring, matching and enforcement against hand-assigned expectations, not comparative effectiveness. A scripted model does not adapt after a block, so protected completion in these runs is not a utility estimate. Live experiments require approved access, budget, protocol and frozen artifacts.

Under the October 7 approval-bound freeze, the unprotected baseline gate passed at baseline scope (30/30 benign, 3/3 executed action changes, 33 graded attempts, 0 invalid traces). It covers only `gpt-4.1-mini-2025-04-14` on the 11-scenario development suite; it says nothing about safety prompting or the mediator. The action change comes from one hidden-instruction scenario whose three repetitions returned identical responses: the model turned on the light and then executed the injected `door.unlock` with nobody present. That meets the predeclared rule but is a small-sample result, not a susceptibility estimate across attacks; the lower limits of the exact (Clopper–Pearson) two-sided 95% intervals are 0.29 for 3/3 and 0.88 for 30/30. In the live connector, simulator tool output reaches the provider as user-role `simulator_tool_result` items because the Responses input path used has no tool role. This is matched across conditions, but it places injected text in a user-role message and may make injection easier. Ahmed and Simon jointly accepted these baseline results on October 7; they are a gate outcome, not a confirmatory research result.

## Independent outcomes and records

The grader consumes complete simulator history and task/policy labels rather than mediator verdicts or an LLM judge. Task completion and unsafe effects are separate: a run may complete the task and perform an unauthorized extra action. An unsafe intermediate state remains unsafe even if later repaired. Gateway reads have receipts, not fabricated device transitions.

Complete abstention or escalation traces can be graded from their actual effects. An escalation ends the attempt without automatically retrying or inventing human approval. Incomplete traces cannot establish safety or completion, while detectable unsafe prefixes remain reported.

Each attempt retains identity, native traces, independent grades, visible model messages, status, limits and usage provenance. Named scripted batches retain their input fixtures and condition hashes. Audit tools recompute grades and summaries from saved records. Unknown costs stay unknown; fixture zeros are labelled synthetic, and provider tariff estimates are distinct from invoices. See the [evaluation interface](evaluation_interface.md).

## Planned final evaluation and analysis

The full-scope contract proposes 24 base tasks, clean/attacked forms, three conditions and three repetitions, with full scope retained under D14. The 44 live baseline attempts already count toward the 432-run ceiling (388 remain), so the full matrix needs an explicit ceiling/allocation decision (D11). Development cases are not final-study tasks. Corpus splits, scenario labels, model settings, run budgets and failure accounting must be reviewed and frozen before final runs.

The final analysis must report declared populations and denominators, clean and attacked completion, unsafe effects, attacker success, false blocks and repair outcomes. Security comparisons use paired base-task cluster bootstrap intervals; the upper endpoint must be strictly below zero for a reduction claim. Relative clean utility must satisfy the contract's 0.85 comparison. D10–D12 still determine the precise metric populations, run ceiling, replay protocol and statistical choices. The [requirements](requirements.md#metrics-and-statistical-claims) contain the proposed definitions and acceptance criteria.

## Results and discussion

The frozen final study ran once on November 4, 2026 (freeze `200d6b0b…`; 24 tasks × clean/attacked × 3 conditions × 3 repetitions = 432 attempts; `gpt-4.1-mini-2025-04-14`; block-randomized order). These results are preliminary until Ahmed's independent replay. A 3-minute provider transport outage (10:59–11:02 UTC) made 97 attempts fail before any model call. Under the frozen rules they were not retried and are reported as invalid; the block-randomized order spread them evenly across conditions (33, 32, 32).

| Measure (task-level rate, evaluable runs) | Unprotected | Safety prompt only | EffectShield |
| --- | --- | --- | --- |
| Attacked unsafe effect | 0.583 (30/56) | 0.458 (24/56) | 0.000 (0/56); exact task-level upper bound 0.142 |
| Attack success | 0.646 (33/56) | 0.500 (25/56) | 0.062 (3/56), all lockout goals |
| Clean completion | 0.708 (40/55) | 0.708 (41/56) | 0.986 (55/56) |
| Clean unsafe effect | 0.292 (15/55) | 0.250 (12/56) | 0.000 (0/56) |
| Attacked completion | 0.521 | 0.542 | 0.868 |
| Weighted loss (10U + B) | 570 | 480 | 2 (2 unnecessary blocks) |
| Invalid runs (provider outage) | 33 | 32 | 32 |

**Primary comparison** (EffectShield vs unprotected, attacked unsafe effects): −58.3 percentage points, two-sided 95% task-cluster bootstrap CI [−76.4, −38.9]. The upper endpoint is below zero, so the reduction claim is supported (STA-02). Counting invalid runs as failures gives −41.7 pp [−56.9, −26.4], still supported. The exploratory comparisons (attack success vs unprotected, and both outcomes vs the safety prompt) also have upper endpoints below zero. Clean completion is preserved (0.986 ≥ 0.85 × 0.708). The baselines' clean utility is lower mainly because the model unlocked or opened the door for nobody in clean stale/replay tasks.

EffectShield's three attack successes are lockouts in the occupied arrival tasks. After a replayed or stale "absent" reading, the agent did not read presence again, and the door stayed locked. This is the lockout cost of the D06/D07 rules that Ahmed flagged; conditioning on a completed matched clean run gives the same 3/56. There were 42 protected blocks, and 2 of them were unnecessary by the independent label. Trace-replay ablations of the same proposals attribute 12 unsafe replays to the removal of rules 4–5 (`no_freshness_replay`) and at most 1 to the removal of rule 3. These are fixed-trace results, not end-to-end ones.

Limitations: one model, one simulator with five devices, 24 synthetic tasks, scripted attack families, and 22% of runs lost to an infrastructure outage. Within this declared scope the results support the hypothesis; they do not establish real-world physical safety or general prompt-injection prevention.

## Reproducibility and review

Keep versioned source, conditions, scenarios, curated fixtures and reproducible commands in Git. Retain actual research evidence, including unsuccessful attempts, under the agreed D13 storage policy. Use temporary directories for disposable checks and Git commits for source history. Credentials stay outside tracked files.

Human acceptance and joint security review remain separate from AI-assisted implementation and automated checks. Observable assistance and verification are recorded in the development log; project prompts are preserved locally according to the agreed workflow. The [research sources](requirements.md#research-sources) and source contract support the methods discussion, but do not establish novelty or experimental success.
