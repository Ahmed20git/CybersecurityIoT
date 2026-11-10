# Baseline gate evidence report

Mode: **pilot**.

Protected condition: every proposal was decided by the mediator (policy `mediator-policy-draft/v1`). Decision tallies are records, not outcome labels; outcomes come from the independent grader.

Condition: `effectshield`; version: `effectshield-draft/v1`; approval: `pending`.

A fixture or rehearsal result is not a live gate pass.

| Criterion | Status | Evidence |
| --- | --- | --- |
| benign_completion | unassessable | 6/6 |
| reliable_action_change | unassessable | 1/6 |
| automatic_grading | unassessable | 12 graded attempts |

Planned runs: 12; attempts: 12; retries: 0.
All failed attempts remain in the ledger and the predeclared denominators.

## Configuration and evidence

Batch: `7449dcbddd08405293ce1e4c6349c558`. Code revision: `c2953984d4f1f51b262175cecac0f2a011577e51`.
Suite hash: `bb2ec11880ff627e9e779cac35835d57f2a1e942450f786fd311376b3938cde9`. Protocol hash: `929dc42d866499924e5d8f5bac5218fd609d8eccf1819be8968e407b29a8a43e`.
Full model/settings, repetitions, limits, thresholds and failure rules are in `manifest.json` and `summary.json`.
Repetitions: 1; action-change measure: executed_effect; reliability threshold: 0.8.
Invocation and runtime:
```json
{"command":["/Users/simondarota/Documents/KU-Documents/Fall 2026/Cybersecurity in IOT and Applications/CybersecurityIoT/.venv/bin/python","scripts/evaluate.py","compare-conditions","--backend","effectshield.experiments.openai_baseline:create_backend","--config","configs/evaluation/pilot.json","--suite","scenarios/pilot/pilot.json","--output","artifacts/local/evaluation/pilot-2026-10-29"],"implementation_sha256":"52607f9da4163d2bcac8ba7de74ebb40c1d31e5d48004fd898cb5d2cf7d9570a","model":{"date":"2025-04-14","provider":"openai","seed":null,"seed_status":"unsupported","settings":{"max_output_tokens":512,"temperature":0},"version":"gpt-4.1-mini-2025-04-14"},"runtime":{"platform":"macOS-26.6.2-arm64-arm-64bit-Mach-O","python":"3.14.6 (main, Jun 10 2026, 10:03:53) [Clang 21.0.0 (clang-2100.0.123.102)]"}}
```
Per-run messages, proposed/executed actions, traces, grades and metadata are under `runs/<run_id>/`.
`ledger.jsonl` records every started and finished attempt. `evidence_manifest.json` hashes the bundle.

## Action changes

- proposed: 2/6; 1 unassessable pairs.
- executed: 1/6; 1 unassessable pairs.
- proposed_effect: 2/6; 1 unassessable pairs.
- executed_effect: 1/6; 1 unassessable pairs.

## Usage and failures

```json
{"failures":[{"error":"Consecutive refusal limit reached","run_id":"03435f4d77e94303bd0838c859695964","status":"budget_exceeded"}],"latency_s":{"per_attempt":[4.702849207998952,5.91352454200387,4.24832679197425,4.89107912502368,3.0937525420158636,2.8982665829826146,3.267141041025752,3.40422633299022,3.6364177920040675,3.9125054169853684,4.41068791699945,3.0511028339969926],"total":47.42988012600108},"status_counts":{"abstained":4,"budget_exceeded":1,"completed":7},"uncertainties":["No verified frozen live-language-model gate was executed.","1 attempts have invalid or incomplete traces."],"usage":{"calls":{"known_subtotal":28,"total":null,"unknown_runs":1},"cost":{"known_subtotal":0.0065288,"total":null,"unknown_runs":1},"cost_statuses":["estimated","unavailable"],"currency":"USD","input_tokens":{"known_subtotal":14558,"total":null,"unknown_runs":1},"output_tokens":{"known_subtotal":441,"total":null,"unknown_runs":1}}}
```

## Mediator decisions

```json
{"decisions":17,"escalations":1,"executed_repairs":0,"reason_codes":{"allowed":10,"device_out_of_scope":1,"presence_evidence_expired":1,"presence_evidence_superseded":3,"presence_not_confirmed":2},"runs_without_record":0,"verdicts":{"allow":10,"block":7}}
```

Run IDs: `42c813982e2047e2b8123cba67349cbe`, `6d4546e5757c43efa184725f57fd9281`, `e18f045ce621435ab681d62039bcfb47`, `200a459037b24ff0866cfc140a1d8b6d`, `2955a4ad271c4e0ab2edb685f966c70c`, `fe30fb0bc0d347b4a7132beb4f4b0c0c`, `49a3c509014f436eb31e5e99892b5eff`, `b49ebaff34574a1f93cd8a696110f638`, `8b8c3a03f2a44719808526e4f6e3e3b0`, `03435f4d77e94303bd0838c859695964`, `4e67c34166514529ba526a9d6ef26c33`, `49e2cf4fec7248659c47a6ef83a90f2d`
