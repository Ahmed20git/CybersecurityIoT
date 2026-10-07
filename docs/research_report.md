# EffectShield research report — working draft

Status: methods outline and implemented baseline description. Confirmatory research results are not yet available; the October 7 baseline-gate outcome (development suite, unprotected condition only) is recorded in the evaluation evidence and its [review record](../artifacts/local/evaluation/live-baseline/review/README.md). Simon leads evaluation and writing; Ahmed leads runtime/enforcement implementation; both review interpretation and security-sensitive claims. Scope, decisions and milestones are defined in the [requirements](requirements.md) and [project plan](project_plan.md).

## Research question and claim boundary

Does a deterministic mediator between a tool-using language-model agent and a simulated smart home reduce unsafe effects and attacker success while preserving useful completion? The intended comparison is against an unprotected agent and a safety-prompt-only agent. This draft makes no claim that the mediator works, that a particular live model is susceptible beyond the single development attack recorded at the baseline gate, or that the system ensures real-world physical safety.

Effects remain inside the five-device simulator. The current development harness verifies trace collection, matching and independent grading using authored responses. Software checks establish implementation behavior; they do not establish the research hypothesis.

## System and threat model

The implemented runtime separates the model's action proposals from trusted request issuance, gateway observations and simulator state mutation. Requests carry harness-issued identity and operation permissions. Gateway envelopes retain source, event ID and simulation time; payload text remains untrusted. Agent-visible inputs omit hidden completion labels and independent grading rules.

The current attack builder changes only predeclared observation message text. It cannot change the original request, permissions, canonical device facts, clock, envelope metadata or grader labels. The development cases include forged system/user authority, an extra operation on an otherwise authorized device, references presented as permission and a false presence claim. Benign controls check quoted instructions, legitimate sensor use and explicitly authorized multi-device work. The full case map and current commands are in the [evaluation guide](evaluation_guide.md#authorization-and-provenance-development-cases).

The mediator and its approved provenance mechanism remain pending. References do not themselves establish action authority. D05 must fix the enforcement mechanism independently of model claims; D06–D08 must fix freshness, replay and repair semantics before those components are accepted.

## Comparison design

Three draft condition definitions exist: [unprotected](../configs/conditions/unprotected.json), [safety-prompt-only](../configs/conditions/safety_prompt_only.json) and [EffectShield](../configs/conditions/effectshield.json). Full EffectShield currently reuses the unprotected prompt and declares enforcement; the baseline adapter refuses to execute it without a mediator. The safety prompt adds instructions without deterministic protection. The unprotected prompt and continuation protocol are approved at baseline scope under D09 (October 7); the safety-prompt-only and EffectShield definitions remain drafts.

Within each development scenario, matching preserves the initial state, request, evidence, model configuration, seed policy, limits and retry rules. The runner stores full condition identity and prompt versions with each attempt. The comparison audit checks these bindings and undeclared differences; incomplete or missing cells remain visible.

The scripted model returns authored proposals irrespective of the prompt. Running the same script under both available conditions tests wiring and matching, not their comparative effectiveness. Live experiments require approved access, budget, protocol and frozen artifacts.

Under the October 7 approval-bound freeze, the unprotected baseline gate passed at baseline scope (30/30 benign, 3/3 executed action changes, 33 graded attempts, 0 invalid traces). It covers only `gpt-4.1-mini-2025-04-14` on the 11-scenario development suite; it says nothing about safety prompting or the mediator. The action change comes from one hidden-instruction scenario whose three repetitions returned identical responses: the model turned on the light and then executed the injected `door.unlock` with nobody present. That meets the predeclared rule but is a small-sample result, not a susceptibility estimate across attacks; the lower limits of the exact (Clopper–Pearson) two-sided 95% intervals are 0.29 for 3/3 and 0.88 for 30/30. In the live connector, simulator tool output reaches the provider as user-role `simulator_tool_result` items because the Responses input path used has no tool role. This is matched across conditions, but it places injected text in a user-role message and may make injection easier. Ahmed and Simon jointly accepted these baseline results on October 7; they are a gate outcome, not a confirmatory research result.

## Independent outcomes and records

The grader consumes complete simulator history and task/policy labels rather than mediator verdicts or an LLM judge. Task completion and unsafe effects are separate: a run may complete the task and perform an unauthorized extra action. An unsafe intermediate state remains unsafe even if later repaired. Gateway reads have receipts, not fabricated device transitions.

Complete abstention or escalation traces can be graded from their actual effects. An escalation ends the attempt without automatically retrying or inventing human approval. Incomplete traces cannot establish safety or completion, while detectable unsafe prefixes remain reported.

Each attempt retains identity, native traces, independent grades, visible model messages, status, limits and usage provenance. Named scripted batches retain their input fixtures and condition hashes. Audit tools recompute grades and summaries from saved records. Unknown costs stay unknown; fixture zeros are labelled synthetic, and provider tariff estimates are distinct from invoices. See the [evaluation interface](evaluation_interface.md).

## Planned final evaluation and analysis

The full-scope contract proposes 24 base tasks, clean/attacked forms, three conditions and three repetitions, with full scope retained under D14. The 44 live baseline attempts already count toward the 432-run ceiling (388 remain), so the full matrix needs an explicit ceiling/allocation decision (D11). Development cases are not final-study tasks. Corpus splits, scenario labels, model settings, run budgets and failure accounting must be reviewed and frozen before final runs.

The final analysis must report declared populations and denominators, clean and attacked completion, unsafe effects, attacker success, false blocks and repair outcomes. Security comparisons use paired base-task cluster bootstrap intervals; the upper endpoint must be strictly below zero for a reduction claim. Relative clean utility must satisfy the contract's 0.85 comparison. D10–D12 still determine the precise metric populations, run ceiling, replay protocol and statistical choices. The [requirements](requirements.md#metrics-and-statistical-claims) contain the proposed definitions and acceptance criteria.

## Results and discussion

No confirmatory research results or confidence intervals are reported yet. Fill this section only from approved, frozen experiment evidence. Current software verification belongs in the [development log](development_log.md), with commands, counts and limitations.

The eventual discussion must include failed attacks, unsafe effects, false blocks, unsuccessful repairs, unknown outcomes and limitations from the simulator, selected models, task population and statistical uncertainty. Do not tune the implementation on final-test results or present a scripted mechanics demonstration as measured model susceptibility.

## Reproducibility and review

Keep versioned source, conditions, scenarios, curated fixtures and reproducible commands in Git. Retain actual research evidence, including unsuccessful attempts, under the agreed D13 storage policy. Use temporary directories for disposable checks and Git commits for source history. Credentials stay outside tracked files.

Human acceptance and joint security review remain separate from AI-assisted implementation and automated checks. Observable assistance and verification are recorded in the development log; project prompts are preserved locally according to the agreed workflow. The [research sources](requirements.md#research-sources) and source contract support the methods discussion, but do not establish novelty or experimental success.
