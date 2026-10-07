# Baseline gate evidence report

Mode: **baseline**.

Condition: `safety_prompt_only`; version: `safety-prompt-only-draft/v1`; approval: `pending`.

A fixture or rehearsal result is not a live gate pass.

| Criterion | Status | Evidence |
| --- | --- | --- |
| benign_completion | unassessable | 30/30 |
| reliable_action_change | unassessable | 21/21 |
| automatic_grading | unassessable | 51 graded attempts |

Planned runs: 51; attempts: 51; retries: 0.
All failed attempts remain in the ledger and the predeclared denominators.

## Configuration and evidence

Batch: `4cc23887bfcf4f84b73819ed488c5f5e`. Code revision: `334c96ca979fefd9724bcfd28d618413b94f292f`.
Suite hash: `3f3c668e8abd7b4d89a8bbe6bc18140291b9aa4bd1fe46179791a2a16820982b`. Protocol hash: `5514f91965bc36b6e4bac0288fadfdbf19f42c88721e371db1317e2437817471`.
Full model/settings, repetitions, limits, thresholds and failure rules are in `manifest.json` and `summary.json`.
Repetitions: 3; action-change measure: executed; reliability threshold: 0.8.
Invocation and runtime:
```json
{"command":["/Users/simondarota/Documents/KU-Documents/Fall 2026/Cybersecurity in IOT and Applications/CybersecurityIoT/.venv/bin/python3","scripts/evaluate.py","compare-baselines"],"implementation_sha256":"9a5bf971c3d9081445b563bbd85e01a67bead206c2706ab86119921a26e069ee","model":{"date":"2026-09-28","provider":"scripted-model","seed":0,"seed_status":"supported","settings":{},"version":"scripted-model-v1"},"runtime":{"platform":"macOS-26.6.2-arm64-arm-64bit-Mach-O","python":"3.14.6 (main, Jun 10 2026, 10:03:53) [Clang 21.0.0 (clang-2100.0.123.102)]"}}
```
Per-run messages, proposed/executed actions, traces, grades and metadata are under `runs/<run_id>/`.
`ledger.jsonl` records every started and finished attempt. `evidence_manifest.json` hashes the bundle.

## Action changes

- proposed: 21/21; 0 unassessable pairs.
- executed: 21/21; 0 unassessable pairs.

## Usage and failures

```json
{"failures":[],"latency_s":{"per_attempt":[0.11269016600272153,0.1156665000016801,0.11242412499996135,0.1160352920051082,0.11259733399492688,0.11426275000121677,0.11028087500017136,0.11437170800491003,0.11549504199501825,0.11649408400262473,0.11088729200128,0.11708862500381656,0.11285983300331281,0.1205797500006156,0.11041841700352961,0.1087239589978708,0.11839983300160384,0.11126954200153705,0.11148850000608945,0.11560170799930347,0.11874729199917056,0.11726466700201854,0.15984729200135916,0.10935774999961723,0.12205958300182829,0.11310450000019046,0.11728625000250759,0.11065720800252166,0.11101562499970896,0.10710762500093551,0.11030395900161238,0.10643166599766118,0.1161764169955859,0.12142750000202795,0.11118754200288095,0.1162865000005695,0.1073644999996759,0.11283349999575876,0.10757279099925654,0.11074733399436809,0.10754979200282833,0.11105254200083436,0.10773524999967776,0.11187104199780151,0.10775641700456617,0.1145522080041701,0.1095957079960499,0.1112648749985965,0.1077187499977299,0.10759666699595982,0.1106255000049714],"total":5.791733587029739},"status_counts":{"completed":51},"uncertainties":["No verified frozen live-language-model gate was executed."],"usage":{"calls":{"known_subtotal":0,"total":0,"unknown_runs":0},"cost":{"known_subtotal":0.0,"total":0.0,"unknown_runs":0},"cost_statuses":["synthetic"],"currency":"USD","input_tokens":{"known_subtotal":0,"total":0,"unknown_runs":0},"output_tokens":{"known_subtotal":0,"total":0,"unknown_runs":0}}}
```

Run IDs: `083e7dc618c54d4eaef7d214df5f9452`, `3abe3a9d79544bb5be43c9f4e5f37b38`, `a7db5c3733d7496d83d23d345d202240`, `fae616bb44524635a7b9f4ec25aa1b76`, `362067348fb4420d8fd35149ac45b5b8`, `58f51ca5bf574441a3786c5b154c2d66`, `74e09192008a45648a0a49ff4b5079ae`, `48850a022df4430bb110a3176b772bc0`, `a4329c6320944966b94584b8f6c14e7b`, `bf0bbf26d67c4289bb102384ce4b3909`, `e182eb8e27894c34904718885d896759`, `0e8e0305f8d54bb8ac7df081892212f6`, `e6720d82ce604617bbc0a4267218dc4a`, `b9860a4784044d8493cfe5dba07117ca`, `863711a729fd49e6807e370a6f216a63`, `be56f4daed344da49812ce190f9ba47f`, `9bc940e46b9d433f8295c2f1a022dd26`, `975da3d677cd4537b1f5203b7ac9b228`, `3abed7636d744f589be7d526bbcc4a7f`, `a81acf2868c54c0296bf4d51efb43abb`, `85075aabc2c24dfd8e1193b0310f41ed`, `7c2e1700d6394b9ab385a54b6046f909`, `063502d85975427f87d7fa62a37c0783`, `eed9d15a3382427da6d88323ea881d5f`, `9ebb8fbac9f044d7bdc921519864f36b`, `ddfdb35c03f840ab9cc5aff96a8319f0`, `74f381eb569e4f65a114de9befd6504b`, `58070d0fc85a4c9aa5752042ca62c721`, `989b044c6457410da62e4d5c064c5951`, `741b919082a44367a18ddf0fb88b6314`, `ea25a7e83d8d4fd18eec016060d12879`, `98eb973b4da34487a3acc26f8cb9140c`, `5a814c8626854d278a576b5de4b155a2`, `323157e7171246dda63f0e7eda3487f1`, `96ea80dbf76d43e6bddf2ad47673d72b`, `5af094b534a34ead947e2438d6906b50`, `d58da8a77a28442e99f5cffbd85ff819`, `afac5f9c561840468ccbbaf9e34f7dfe`, `d17183e109ba402f956b56a33b881781`, `0ab7548ba6bd4aeb9286b8c33f798ff2`, `1eb634b950da4810b3054a3856ad6c6d`, `c015a5a5174d4476aaada74f6ec9153e`, `211deb4d494a46f4983f84fff232f18a`, `9c9d8a6441e14dca9b606f2b79d6d82f`, `c04086c45e8b4cdcac2e290ba8b928a6`, `0cbb565632a0412396071ef232006fa5`, `b02a2da93c674fe9bf6a8d35e356f81b`, `ef1e98a66ebb40bf87c646fb0ffb03dc`, `913cb02d2060469f868259709c4b1e14`, `86496a43919f448f8fe27588e0c22dc2`, `f5879383b8f64baaa265f67f7b12fb14`
