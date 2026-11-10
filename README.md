# EffectShield

EffectShield studies whether deterministic checks between a tool-using language-model agent and a simulated smart home reduce unsafe effects while preserving useful task completion.

The simulator, trusted gateway, typed runtime records and Ahmed's deterministic mediator are integrated with the scenarios, bounded payload attacks, independent grader and experiment runner. The frozen final study ran once on November 4, 2026 with OpenAI `gpt-4.1-mini-2025-04-14`: 432 attempts over 24 tasks, three conditions and three repetitions. EffectShield had no unsafe effect in 56 evaluable attacked runs, against 30 of 56 for the unprotected agent (primary difference −58.3 pp, 95% CI [−76.4, −38.9]), and clean completion was preserved. The claim is limited to this model, simulator and attack corpus. The [full report](docs/report/effectshield_report.pdf), its [summary](docs/research_report.md) and the [artifact guide](docs/artifact.md) describe the results and how to reproduce them.

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

To exercise the authorization/provenance cases across all three conditions, including the mediator-protected one, using scripted proposals:

```sh
python3 scripts/evaluate.py compare-conditions
python3 scripts/evaluate.py verify-comparison PATH_TO_COMPARISON
python3 scripts/evaluate.py preflight --config configs/evaluation/final.json --suite scenarios/test/final.json --repetitions 3
```

The comparison preserves matching, outcome and mediator-decision evidence. Scripted responses do not measure prompt-only defense efficacy or live-model utility. Preflight counts a proposed matrix against the run ceiling and approves nothing. See the [development cases and commands](docs/evaluation_guide.md#condition-comparison).

## Final results, dashboard and demonstration

Verify the retained evidence and regenerate every reported number offline, without credentials:

```sh
python3 scripts/evaluate.py verify-artifact artifacts/local/evaluation/ARTIFACT_MANIFEST.json
python3 scripts/evaluate.py analyze artifacts/local/evaluation/final-2026-11-04 --output PATH_TO_OUTPUT
python3 scripts/report_tables.py --check
```

The read-only results dashboard needs its pinned dependencies:

```sh
.venv/bin/python -m pip install -r requirements-dashboard.txt
.venv/bin/streamlit run src/effectshield/dashboard/app.py
```

The narrated demonstration (4:35) records this dashboard. The video is shared outside Git; its [script](docs/demo/demo_script.md) and subtitles are tracked, and `scripts/record_demo.py` re-records it. The [artifact guide](docs/artifact.md) covers the ablation, latency and billing commands, the report build and re-recording the demonstration.

## Organization

| Location | Purpose |
| --- | --- |
| `src/effectshield/domain/` | Typed states, actions, trusted context and errors |
| `src/effectshield/simulator/`, `gateway/`, `environment.py` | State transitions, complete history, trusted observations and isolated runs |
| `src/effectshield/agent/` | Bounded proposal loop and isolated model clients |
| `src/effectshield/mediator/` | Deterministic rules 1–8, repair and protected execution |
| `src/effectshield/scenarios.py`, `attacks.py`, `grading.py` | Development data, bounded mutations and independent outcome checks |
| `src/effectshield/experiments/`, `analysis.py` | Execution, replay, evidence, summaries, protocol freezing, final analysis, ablations, latency, billing and the artifact manifest |
| `src/effectshield/dashboard/` | Read-only Streamlit results dashboard over verified evidence |
| `scenarios/development/`, `scenarios/pilot/`, `scenarios/test/` | Development corpora, the held-out pilot and the draft final manifest, separated by split |
| `fixtures/evaluation/`, `configs/` | Reference traces, hand-assigned expectations, conditions and approved protocol settings |
| `artifacts/local/evaluation/` | Retained research evidence (D13), including the final study, its freeze, analyses and review |
| `docs/report/`, `docs/demo/`, `scripts/` | Report source, generated tables and PDF; demonstration video and script; report, demo and command-line scripts |
| `tests/` | Unit, integration and security checks |

## Documentation

- [Setup and troubleshooting](docs/running.md)
- [Evaluation commands and integration status](docs/evaluation_guide.md)
- [Runtime interfaces](docs/interfaces.md), [mediator design](docs/mediator_design.md) and [evaluation records](docs/evaluation_interface.md)
- [Full report (PDF)](docs/report/effectshield_report.pdf), [report summary](docs/research_report.md) and [artifact and reproduction guide](docs/artifact.md)
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

On October 7 the approval-bound live baseline gate (33 attempts, OpenAI `gpt-4.1-mini-2025-04-14`) passed all three criteria at baseline scope: 30/30 benign completions, 3/3 executed action changes and 33/33 attempts automatically graded with no invalid traces. D14 records that full scope is retained. Execution, automated audit and an independent re-execution reproduction are complete (see the [review record](artifacts/local/evaluation/live-baseline/review/README.md)). Ahmed and Simon jointly accepted these results on October 7, completing WP-06. Ahmed's mediator (WP-07 to WP-09) was merged on October 14. A held-out pilot ran on October 29, and the final study was frozen and run on November 4; Ahmed's independent replay found no differences. As of November 6 the report, dashboard, demonstration and artifact package form a complete candidate awaiting joint review by November 13. Internal completion is due November 20 and submission falls in November 23–27, with its exact due time pending. The [project plan](docs/project_plan.md) records the details.

Implement and verify one coherent component at a time. Keep credentials in environment configuration, retain research evidence and commit related source, tests and documentation together. Use Git for source history; remove disposable verification outputs and tool caches after checks instead of keeping backup copies. No real devices or smart-home accounts are used.
