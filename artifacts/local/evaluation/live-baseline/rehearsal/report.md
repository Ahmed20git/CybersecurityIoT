# Baseline gate evidence report

Mode: **rehearsal**.

A fixture or rehearsal result is not a live gate pass.

| Criterion | Status | Evidence |
| --- | --- | --- |
| benign_completion | unassessable | 10/10 |
| reliable_action_change | unassessable | 1/1 |
| automatic_grading | unassessable | 11 graded attempts |

Planned runs: 11; attempts: 11; retries: 0.
All failed attempts remain in the ledger and the predeclared denominators.

## Configuration and evidence

Batch: `93815048da4b41d9875c5830a8e8e442`. Code revision: `a9786d12167eacd28fdd00c386b1f9d6458f8533`.
Suite hash: `67e295498a807d89002fdee67fa9ddf9747f33a6ea7dd6ba56b677d3fd791c45`. Protocol hash: `0972a981acd950e54a3fef2d4fe9d8f7f2ecd72e1de7304e41c9e9f133ee2924`.
Full model/settings, repetitions, limits, thresholds and failure rules are in `manifest.json` and `summary.json`.
Repetitions: 1; action-change measure: executed; reliability threshold: 0.8.
Invocation and runtime:
```json
{"command":["/Users/simondarota/Documents/KU-Documents/Fall 2026/Cybersecurity in IOT and Applications/CybersecurityIoT/.venv/bin/python","scripts/evaluate.py","rehearsal","--config","artifacts/local/evaluation/live-baseline/rehearsal_protocol.json","--backend","effectshield.experiments.openai_baseline:create_backend","--output","artifacts/local/evaluation/live-baseline/rehearsal"],"implementation_sha256":"9a5bf971c3d9081445b563bbd85e01a67bead206c2706ab86119921a26e069ee","model":{"date":"2025-04-14","provider":"openai","seed":null,"seed_status":"unsupported","settings":{"max_output_tokens":512,"temperature":0},"version":"gpt-4.1-mini-2025-04-14"},"runtime":{"platform":"macOS-26.6.2-arm64-arm-64bit-Mach-O","python":"3.14.6 (main, Jun 10 2026, 10:03:53) [Clang 21.0.0 (clang-2100.0.123.102)]"}}
```
Per-run messages, proposed/executed actions, traces, grades and metadata are under `runs/<run_id>/`.
`ledger.jsonl` records every started and finished attempt. `evidence_manifest.json` hashes the bundle.

## Action changes

- proposed: 1/1; 0 unassessable pairs.
- executed: 1/1; 0 unassessable pairs.

## Usage and failures

```json
{"failures":[],"latency_s":{"per_attempt":[6.2563479999953415,3.217940250004176,6.204720334004378,5.526867499997024,4.561902124994958,4.570188541998505,3.586244042002363,5.374936000000162,3.5413520419970155,3.659567499998957,7.293512708994967],"total":53.79357904398785},"status_counts":{"completed":11},"uncertainties":["No verified frozen live-language-model gate was executed."],"usage":{"calls":{"known_subtotal":23,"total":23,"unknown_runs":0},"cost":{"known_subtotal":0.0049496,"total":0.0049496,"unknown_runs":0},"cost_statuses":["estimated"],"currency":"USD","input_tokens":{"known_subtotal":11010,"total":11010,"unknown_runs":0},"output_tokens":{"known_subtotal":341,"total":341,"unknown_runs":0}}}
```

Run IDs: `079afe8a351546459ddcb143436a922c`, `0329842482ed40eca3d3d02d75cf2611`, `e720b882c83549d79c9a73df8e0069f5`, `da77a3c5df844f06bef5094fa666f5a8`, `f9867fa4d61d4557b309d1134dc24b5f`, `f032954651d34030a5da920735e4c2f4`, `cae47823e92b47e9a6905468b6747a3e`, `7be7aafd686d412594c28588ceec122f`, `dd12d1c51b2c43e1a2c90fe8891f0cff`, `6881179a2bbe438dbf8072fc7a6e7fbb`, `32cb901c4e1a4b6eab3654f1acee8272`
