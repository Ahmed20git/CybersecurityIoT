# EffectShield

EffectShield studies whether deterministic checks between a tool-using language-model agent and a simulated smart home reduce unsafe effects while preserving useful task completion.

The simulator, trusted gateway and typed runtime records are integrated with the development scenarios, bounded payload attacks, independent grader and experiment runner. A recorded-proposal replay exercises the actual simulator. The bounded baseline agent adapter uses the same runtime and supports a scripted test model plus a separate OpenAI connector. Live gate results require a reviewed provider, model, budget and protocol; offline results do not establish model performance.

## Run locally

Python 3.11 or later is required. Runtime code uses the standard library.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pip install -e .
.venv/bin/python scripts/evaluate.py offline
.venv/bin/python scripts/evaluate.py simulator-replay
.venv/bin/python scripts/evaluate.py baseline
```

Each command creates a separate evidence directory under ignored `artifacts/local/evaluation/`, containing traces, automatic grades, a run ledger, configuration and a report. The replay command executes recorded proposals through the real simulator and gateway; `baseline` also exercises the bounded agent using scripted model responses. All three commands run without live model calls.

```sh
.venv/bin/python -m pytest
.venv/bin/ruff check src tests scripts examples
.venv/bin/ruff format --check src tests scripts examples
.venv/bin/mypy
```

## Organization

| Location | Purpose |
| --- | --- |
| `src/effectshield/domain/` | Typed states, actions, trusted context and errors |
| `src/effectshield/simulator/`, `gateway/`, `environment.py` | State transitions, complete history, trusted observations and isolated runs |
| `src/effectshield/agent/` | Bounded proposal loop and isolated model clients |
| `src/effectshield/scenarios.py`, `attacks.py`, `grading.py` | Development data, bounded mutations and independent outcome checks |
| `src/effectshield/experiments/` | Execution, replay, evidence, summaries and protocol freezing |
| `scenarios/development/`, `fixtures/evaluation/`, `configs/evaluation/` | Versioned tasks, labelled fixtures and draft gate settings |
| `tests/` | Unit, integration and security checks |

## Documentation

- [Evaluation commands and integration status](docs/evaluation_guide.md)
- [Runtime interfaces](docs/interfaces.md) and [evaluation records](docs/evaluation_interface.md)
- [Requirements](docs/requirements.md) and [project plan](docs/project_plan.md)
- [Development and verification log](docs/development_log.md)
- [Source research contract](docs/reference/EffectShield_Revised_Research_Project_Contract.docx)

Local working notes include `docs/baseline_tasks.md`, `docs/review_and_decisions.md`, `docs/research_basis.md`, `docs/prompts_history.md` and `AGENTS.md`. They retain the existing ignore choices. The tracked guides above contain the reproducible commands and current integration status.

## Responsibilities and schedule

| Owner | Responsibility |
| --- | --- |
| Ahmed | Simulator, gateway, typed runtime interfaces, agent integration and enforcement |
| Simon | Scenarios, attacks, independent grading, experiments, analysis and reproducibility |
| Both | Interface and security reviews, interpretation, report and demonstration |

The original baseline checkpoint was September 25, 2026. As of September 28, no verified live gate result is available; its status remains unassessable pending model access and protocol decisions. The project plan preserves that checkpoint and records the outstanding work. Target a complete candidate by November 6, joint review by November 13 and internal completion by November 20. Submission remains November 23–27, with its exact due time pending.

Implement and verify one coherent component at a time. Keep credentials in environment configuration, retain research evidence and commit related source, tests and documentation together. No real devices or smart-home accounts are used.
