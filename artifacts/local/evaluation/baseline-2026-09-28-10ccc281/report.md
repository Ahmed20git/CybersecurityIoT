# Baseline gate evidence report

Mode: **baseline**.

A fixture or rehearsal result is not a live gate pass.

| Criterion | Status | Evidence |
| --- | --- | --- |
| benign_completion | unassessable | 30/30 |
| reliable_action_change | unassessable | 3/3 |
| automatic_grading | unassessable | 33 graded attempts |

Planned runs: 33; attempts: 33; retries: 0.
All failed attempts remain in the ledger and the predeclared denominators.

## Configuration and evidence

Batch: `83ba11724a44404cafe094ae86aaab37`. Code revision: `1a8979d78ae5ef3fd1a3bf00fb926bdc26569e40`.
Suite hash: `67e295498a807d89002fdee67fa9ddf9747f33a6ea7dd6ba56b677d3fd791c45`. Protocol hash: `363fbb6a57da4ef58992930dc44462d4ea7aec0d4bc410e1b682cbd95275116b`.
Full model/settings, repetitions, limits, thresholds and failure rules are in `manifest.json` and `summary.json`.
Repetitions: 3; action-change measure: executed; reliability threshold: 0.8.
Invocation and runtime:
```json
{"command":["/Users/simondarota/Documents/KU-Documents/Fall 2026/Cybersecurity in IOT and Applications/CybersecurityIoT/.venv/bin/python3","scripts/evaluate.py","baseline"],"implementation_sha256":"a7c09cd38be0423c8b275ef2c6fc5545d3241883df673d877e6f2d5596f80f89","model":{"date":"2026-09-28","provider":"scripted-model","seed":0,"seed_status":"supported","settings":{},"version":"scripted-model-v1"},"runtime":{"platform":"macOS-26.6.2-arm64-arm-64bit-Mach-O","python":"3.14.6 (main, Jun 10 2026, 10:03:53) [Clang 21.0.0 (clang-2100.0.123.102)]"}}
```
Per-run messages, proposed/executed actions, traces, grades and metadata are under `runs/<run_id>/`.
`ledger.jsonl` records every started and finished attempt. `evidence_manifest.json` hashes the bundle.

## Action changes

- proposed: 3/3; 0 unassessable pairs.
- executed: 3/3; 0 unassessable pairs.

## Usage and failures

```json
{"failures":[],"latency_s":{"per_attempt":[0.14243554195854813,0.11930174997542053,0.1236147090094164,0.12027854204643518,0.11588037491310388,0.12224341707769781,0.11737170908600092,0.1153014589799568,0.11781545903068036,0.11533858301118016,0.1332295840838924,0.12058900005649775,0.1291390829719603,0.122434708988294,0.12681133300065994,0.12936629191972315,0.1447444580262527,0.13428466697223485,0.12748570798430592,0.12066404207143933,0.13134641700889915,0.13389595807529986,0.12122570804785937,0.12583166698459536,0.1236670829821378,0.12725529202725738,0.12802362500224262,0.12479583406820893,0.1304940830450505,0.12211100000422448,0.12591883400455117,0.11495516693685204,0.12496033299248666],"total":4.132811422343366},"status_counts":{"completed":33},"uncertainties":["No verified frozen live-language-model gate was executed."],"usage":{"calls":{"known_subtotal":0,"total":0,"unknown_runs":0},"cost":{"known_subtotal":0.0,"total":0.0,"unknown_runs":0},"cost_statuses":["synthetic"],"currency":"USD","input_tokens":{"known_subtotal":0,"total":0,"unknown_runs":0},"output_tokens":{"known_subtotal":0,"total":0,"unknown_runs":0}}}
```

Run IDs: `fb6b99e7f94b44eaaa219269a517a104`, `288e6ef6575d472288d8d3ba3eb76bc4`, `75a993e980f04170876c3cc32db0c196`, `98e23f6c701e4f829767c275903711e7`, `8123dc8baa0145689577832c70315197`, `1f73a40336f149b19fa112ef68b67618`, `e48abc812f6f4882a0ab6789619deac7`, `6c6e1a6cef5f4869be03f9d1e555dcde`, `ddc3810dc04a42d1b55ea0958d8f4b31`, `a88bc27ae786414c8d0008ad808687e9`, `b6e8164a06f64a02b9e6ff1f868febcb`, `9410d3fed64a4853b1a3dba2cd21885d`, `34665a676224434bba64d3588938d6c3`, `fe7f59aa0d5340ea9bfa51621e78f5df`, `7d4fea4d142d48f68f5ccb8c8ae79650`, `44d1386f052c49f487d4e25d74b653d9`, `aa44fc0c51504d4391fd864da7a21469`, `b45f3bcfba1047189194b87dd87759fc`, `c04acee4f3e7485d925fa698980f9d50`, `c8fd782ca6c54516ab5a61f0ee07499b`, `31daca7bde66407eabff5ed627fbcbfc`, `ec5b39a3b43a46a5a0973ea8241b5104`, `fe37ce2486aa486c8fa04439ba93634e`, `266e25afd553440fa56741b5df83d6a9`, `3ec1261c77984d068b87d17b7cd02505`, `7d4ece6f4e33438881b7439816452473`, `a8a428f99c76440492a6979673466fc6`, `15bd107777794c76a3ca3805d0c4f422`, `004db6e1e92c4a9a9e4532f08e2f74a9`, `5c3aba87e79545f397d9569754738be0`, `75220e53be524323a125e00ef738ef77`, `568d22040f0b496eb604bf86e81082ef`, `c76d1fb08a2a46a1bbd8f1f79a6fd081`
