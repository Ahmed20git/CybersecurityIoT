# Independent replay of the November 4 final study

Ahmed's Week 10 check of Simon's final study (freeze `200d6b0b…`, code `1ec6544`, evidence in `../final-2026-11-04/`), made on November 4 from `authorization-evaluation` at `50de87f`. AI-assisted (Claude Code); no live model calls.

## Result: everything reproduces

| Check | How | Result |
| --- | --- | --- |
| Freeze | `verify-freeze ../final-freeze` | Verified (exit 0) |
| Evidence bundles | `verify-evidence` on each condition | Verified: 144 runs each (725, 725 and 869 hashed files) |
| Comparison | `verify-comparison ../final-2026-11-04` | Verified, 144 matched cells, status `incomplete` (invalid runs) |
| Re-grading | `replay.py`: the independent grader on every saved trace against `scenarios/test/final.json` | 0 differences from the saved `grade.json` in 432 runs; every bundle's `suite.json` equals the manifest |
| Offline re-execution | `replay.py`: each valid run's recorded proposals replayed through a fresh simulator (and the mediator for EffectShield) with the same scenario, evidence schedule and task intent | 0 mismatches in executed actions and final state over 335 valid runs (111 / 112 / 112); all 112 protected runs also reproduce every decision's verdict and reason code |
| Headline counts | `replay.py`: own task-level recount (mean over repetitions, then over tasks) without `effectshield.analysis` | Identical to `analysis.json` and the project plan (table below) |
| Primary comparison | `bootstrap.py`: own paired task bootstrap, different seed (1234) | −58.3 pp, 95% CI [−76.4, −38.9], same as reported |
| Analysis | `analyze` into a new file | Identical to the saved `analysis.json` |
| Ablations | `ablate` on each bundle into new files | Identical to the three saved ablation reports |

| Measure (evaluable runs) | Unprotected | Safety prompt only | EffectShield |
| --- | --- | --- | --- |
| Attacked unsafe effect | 30/56 (0.583) | 24/56 (0.458) | 0/56 (0.000) |
| Attack success | 33/56 (0.646) | 25/56 (0.500) | 3/56 (0.062) |
| Clean completion | 40/55 (0.708) | 41/56 (0.708) | 55/56 (0.986) |
| Clean unsafe effect | 15/55 (0.292) | 12/56 (0.250) | 0/56 (0.000) |
| Attacked completion | 31/56 (0.521) | 32/56 (0.542) | 48/56 (0.868) |
| Invalid runs | 33 | 32 | 32 |

## Review of `3d9ae2a` (continuation versions)

Sound. Conditions may record `continuation-draft/v1` or `v2`, so the October 7 comparison and the October 29 pilot stay auditable, and `open_batch` rejects any named condition that is not on the current v2 for new scripted, pilot or final runs. Every evidence-producing path, including the live factory in `openai_baseline.py`, goes through `open_batch`. Direct backend use in tests or examples is not guarded, but it produces no evidence. 2,455 tests pass at `50de87f`.

## Limits

- The re-execution replays recorded proposals; it does not re-query the model, which has no supported seed.
- The 97 invalid runs failed before any model call during the provider outage and cannot be replayed. Their split (33/32/32) and the invalid-as-failure sensitivity are as reported.
- Costs were not reconciled with provider billing.

Commands (repository root, `PYTHONDONTWRITEBYTECODE=1`):

```sh
python3 scripts/evaluate.py verify-freeze artifacts/local/evaluation/final-freeze
python3 scripts/evaluate.py verify-comparison artifacts/local/evaluation/final-2026-11-04
python3 artifacts/local/evaluation/final-2026-11-04-review/replay.py recount.json
python3 artifacts/local/evaluation/final-2026-11-04-review/bootstrap.py
python3 scripts/evaluate.py analyze artifacts/local/evaluation/final-2026-11-04 --output NEW_FILE
python3 scripts/evaluate.py ablate artifacts/local/evaluation/final-2026-11-04/effectshield --output NEW_FILE
```
