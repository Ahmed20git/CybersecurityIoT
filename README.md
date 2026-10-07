# EffectShield

EffectShield studies whether deterministic checks between a tool-using language-model agent and a simulated smart home reduce unsafe effects while preserving useful task completion.

The simulator, trusted gateway and typed runtime records are integrated with the development scenarios, bounded payload attacks, independent grader and experiment runner. A recorded-proposal replay exercises the actual simulator. The bounded baseline agent adapter uses the same runtime and supports a scripted test model plus a separate OpenAI connector. The approval-bound live baseline gate ran on October 7, 2026 with OpenAI `gpt-4.1-mini-2025-04-14` (see the [project plan](docs/project_plan.md#week-4-gate-and-fallback)); offline results do not establish model performance.

## Run locally

Python 3.11 or later is required. Runtime code uses the standard library. See [setup and troubleshooting](docs/running.md) for Windows, macOS/Linux and editor instructions.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pip install -e .
.venv/bin/python scripts/evaluate.py offline
.venv/bin/python scripts/evaluate.py simulator-replay
.venv/bin/python scripts/evaluate.py baseline
```

Each command creates a separate evidence directory under `artifacts/local/evaluation/`, containing traces, automatic grades, a run ledger, configuration and a report. The replay command executes recorded proposals through the real simulator and gateway; `baseline` also exercises the bounded agent using scripted model responses. All three commands run without live model calls. Since October 7 that directory is no longer Git-ignored, so both collaborators can reach retained evidence through Git. Delete disposable verification runs, or write them to a temporary directory, instead of committing them.

To visualize a saved run, replace `PATH_TO_RUN` with the `output` directory printed by the command:

```sh
python3 scripts/evaluate.py visualize PATH_TO_RUN
```

Open the returned HTML file in your browser. It shows batch totals, every attempt, matched clean/attacked runs and a step-by-step device replay. It works offline without a web server or extra dependencies. See the [viewer instructions](docs/evaluation_guide.md#visualize-saved-evidence) for output paths and interpretation.

```sh
.venv/bin/python -m pytest
.venv/bin/ruff check src tests scripts examples
.venv/bin/ruff format --check src tests scripts examples
.venv/bin/mypy
```

To exercise the authorization/provenance cases across both available scripted baseline conditions:

```sh
python3 scripts/evaluate.py compare-baselines
python3 scripts/evaluate.py verify-comparison PATH_TO_COMPARISON
```

The comparison preserves matching and outcome evidence. The protected condition remains `not_run` until the mediator exists; scripted responses do not measure prompt-only defense efficacy. See the [case matrix and commands](docs/evaluation_guide.md#authorization-and-provenance-development-cases) and the [draft research report](docs/research_report.md).

## Organization

| Location | Purpose |
| --- | --- |
| `src/effectshield/domain/` | Typed states, actions, trusted context and errors |
| `src/effectshield/simulator/`, `gateway/`, `environment.py` | State transitions, complete history, trusted observations and isolated runs |
| `src/effectshield/agent/` | Bounded proposal loop and isolated model clients |
| `src/effectshield/scenarios.py`, `attacks.py`, `grading.py` | Development data, bounded mutations and independent outcome checks |
| `src/effectshield/experiments/` | Execution, replay, evidence, summaries and protocol freezing |
| `scenarios/development/`, `fixtures/evaluation/`, `configs/evaluation/` | Versioned tasks, labelled fixtures and approved baseline gate settings |
| `tests/` | Unit, integration and security checks |

## Documentation

- [Setup and troubleshooting](docs/running.md)

- [Evaluation commands and integration status](docs/evaluation_guide.md)
- [Runtime interfaces](docs/interfaces.md) and [evaluation records](docs/evaluation_interface.md)
- [Requirements](docs/requirements.md) and [project plan](docs/project_plan.md)
- [Development and verification log](docs/development_log.md)
- [Live baseline gate review record](artifacts/local/evaluation/live-baseline/review/README.md)
- [Source research contract](docs/reference/EffectShield_Revised_Research_Project_Contract.docx)

The [open decisions](docs/requirements.md#open-decisions) record the October 7 baseline approvals and the remaining final-study, mediator and release decisions. The [project plan](docs/project_plan.md) records the timeline and owner responsibilities.

## Responsibilities and schedule

| Owner | Responsibility |
| --- | --- |
| Ahmed | Simulator, gateway, typed runtime interfaces, agent integration and enforcement |
| Simon | Scenarios, attacks, independent grading, experiments, analysis and reproducibility |
| Both | Interface and security reviews, interpretation, report and demonstration |

On October 7 the approval-bound live baseline gate (33 attempts, OpenAI `gpt-4.1-mini-2025-04-14`) passed all three criteria at baseline scope: 30/30 benign completions, 3/3 executed action changes and 33/33 attempts automatically graded with no invalid traces. D14 records that full scope is retained. Execution, automated audit and an independent re-execution reproduction are complete (see the [review record](artifacts/local/evaluation/live-baseline/review/README.md)). Ahmed and Simon jointly accepted these results on October 7, completing WP-06. No mediator or protected-condition result exists yet. The project plan preserves that checkpoint and records the outstanding work. Target a complete candidate by November 6, joint review by November 13 and internal completion by November 20. Submission remains November 23–27, with its exact due time pending.

Implement and verify one coherent component at a time. Keep credentials in environment configuration, retain research evidence and commit related source, tests and documentation together. Use Git for source history; remove disposable verification outputs and tool caches after checks instead of keeping backup copies. No real devices or smart-home accounts are used.
