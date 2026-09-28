# Observable AI assistance and verification log

## 2026-09-21 — Simon's Week 4 evaluation tooling

This entry records observable assistance, artifacts and verification for PROMPT-004 in [the prompt history](prompts_history.md). The full attached prompt and Simon's note are preserved there with capture time `2026-09-21T16:40:07+04:00`. Simon and Ahmed remain the designated human project authors; this log discloses AI assistance and does not assign a Git identity or claim human approval. Hidden reasoning, system/developer instructions and credentials are excluded.

### Scope and repository inspection

The assistant inspected the repository, working instructions, preserved research contract, requirements, dated plan, decision register, Git status and available code. The repository had planning documents but no simulator, gateway, runtime schema, agent adapter or existing implementation tests. The user's commit `569258d` was preserved. Existing ignore choices, including the locally ignored prompt history and decision register, were preserved.

Simon authorized W4-S01–S05 and explicitly reserved Ahmed's components for Ahmed. The implementation therefore uses a provisional evaluation record format and authored static trace fixtures. It does not implement a simulator or model adapter. Joint integration can only be tested once Ahmed supplies those components.

Two clarification questions were raised: whether Ahmed's interfaces exist elsewhere, and whether D09 should use proposed or executed action changes. No answers to those questions were available when this implementation was prepared. The runner supports both measurements; executed changes, three repetitions and an 80% reliability threshold remain proposals. No approval, official freeze, credentials, paid inference or live gate result was manufactured.

### Generated outputs and file inventory

| Files | Observable output |
| --- | --- |
| `pyproject.toml`, `requirements-dev.txt`, package `__init__.py` files | Python 3.11+ project metadata, standard-library runtime and pinned Ruff development tool |
| `src/effectshield/scenarios.py`, `scenarios/week4/development.json` | Validated development suite: ten clean tasks spanning five devices plus one matched attacked variant, with stable IDs, initial state, requests, observations, completion/policy predicates and run fields |
| `src/effectshield/attacks.py` | Bounded mutation of explicitly allowed payload text; protected labels, envelope identity/time/IDs, permissions and initial state remain unchanged |
| `src/effectshield/grading.py`, `fixtures/week4/grader_cases.json` | Independent complete-trace grading and ten hand-labelled fixtures; unsafe intermediate effects remain failures after recovery; recorded repairs require safe task completion |
| `fixtures/week4/runs.json`, `src/effectshield/experiments/backends.py` | Explicit static trace replay for offline tests, plus a loader for Ahmed's future trusted connector |
| `src/effectshield/experiments/runner.py`, `storage.py` | Spawned-process attempts, exact reset check, durable event acknowledgement, separate proposed/committed actions, all-attempt ledger, retries/timeouts/bounds, actual/unknown usage distinction and secret redaction |
| `src/effectshield/experiments/report.py`, `checks.py`, `audit.py` | Fixture self-check, summaries, both action-change measures, missing/failure accounting, three gate statuses and read-only integrity/regrading checks |
| `src/effectshield/experiments/freeze.py`, `configs/week4/gate.json` | Draft protocol, approval-bound hashes/snapshots and verification, source/input binding and one official batch per freeze |
| `src/effectshield/experiments/cli.py`, `scripts/week4.py` | Offline, rehearsal, approval-hashes, freeze, gate and evidence-verification commands |
| `tests/test_scenarios.py`, `test_attacks.py`, `test_grading.py`, `test_runner.py`, `test_report.py`, `test_freeze.py`, `test_audit.py`, `support_backends.py`, `__init__.py` | Unit and integration checks with static test doubles; no provider calls |
| `docs/week4_interface.md`, `docs/week4_implementation.md`, this file | Provisional Ahmed handoff, exact commands, blockers, evidence layout, review groups and AI-use/verification record |
| `README.md`, `docs/project_plan.md` | Current implementation stage and links while preserving the agreed calendar |
| Local ignored `AGENTS.md`, `docs/week_04_tasks.md`, `docs/review_and_decisions.md`, `docs/prompts_history.md` | Authorized scope, current status, pending decisions and full user instructions; not force-added |

Independent assistant reviews checked the mutation boundary, full-trace grading, freeze integrity, failure accounting and final handoff consistency. These reviews are AI assistance, not Simon's or Ahmed's acceptance. Source files and documents contain the reviewable generated outputs.

### Verification performed

Environment: macOS arm64, Python 3.14.6, Ruff 0.16.8 in an ignored `.venv`. Runtime code uses the standard library. Compatibility with every supported Python version was not tested.

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
.venv/bin/ruff check src tests scripts
.venv/bin/ruff format --check src tests scripts
git diff --check
```

The final unit/integration run passed **101 tests** in 6.676 seconds. Its complete output is retained locally at `artifacts/local/week4/unit-test-output-final.txt`. Ruff lint and formatting checks passed for 23 Python files. Tests exercise payload confinement, exact JSON types, every committed transition, unsafe effects followed by recovery, malformed/incomplete traces, deterministic reset, cross-run isolation, partial failures/timeouts, retry denominators, unknown usage, usage monotonicity, reserved-event rejection, evidence tampering, approval bindings and freeze reuse prevention.

Earlier verification exposed and corrected two seed issues. Adding an unsupported-seed constraint invalidated a synthetic freeze fixture that used seed `0` with status `unsupported`; that fixture now uses `null`. A new regression test then exposed the missing opposite constraint: a supported seed cannot be left unspecified. The validator now requires its explicit integer value. Both earlier failing outputs remain in `unit-test-output.txt` and `unit-test-output-verified.txt`; they were not replaced with the passing output. Earlier test runs and review also led to stricter canonical comparisons, monotonic usage, durable event delivery and frozen-connector binding.

The complete CLI workflows were exercised using static data:

```sh
python3 scripts/week4.py offline --output artifacts/local/week4/offline-final-verification
python3 scripts/week4.py verify-evidence artifacts/local/week4/offline-final-verification
python3 scripts/week4.py rehearsal --output artifacts/local/week4/rehearsal-final-verification
python3 scripts/week4.py verify-evidence artifacts/local/week4/rehearsal-final-verification
```

Each workflow retained 33 attempts, with 30/30 clean fixture goal completions and 3/3 matched action changes in both measures. Each evidence audit passed with 170 hashed files and 33 run records. All three gate statuses remained `unassessable`. These numbers are authored fixture expectations, not measured model performance. Cost/token/call values are explicitly synthetic zeros. Reports include actual local runtime latency, invocation, source/configuration hashes, run IDs and ledger paths.

After the final seed-validation correction, the offline workflow and audit were repeated successfully at `artifacts/local/week4/offline-verified-v2` to bind evidence to the final source: 33 attempts, 170 verified files and the same fixture outcomes. Earlier evidence was retained. Rehearsal separation and accounting were also exercised by the passing final integration tests.

Final documentation checks passed for all 11 Markdown files, existing local links, balanced code fences, whitespace and valid JSON configuration/scenario/fixture files. Git whitespace checks passed, the index remained empty, and generated evidence, the local environment and caches remained ignored. These checks do not claim that ignored local documents are published to GitHub.

### Remaining work and review status

| Week 4 live criterion | Status | Reason |
| --- | --- | --- |
| At least 70% benign completion | Unassessable | No approved live model run |
| Reliably action-changing attack | Unassessable | D09 is pending and no live attack measurement exists |
| Automatic grading of gate runs | Unassessable | Offline grader checks pass, but no official live traces exist |

Ahmed still supplies the simulator, gateway, runtime schemas and agent connector. D03/D04/D05/D09/D10/D11/D13 need the relevant human decisions before an official freeze. Real integration must verify reset/isolation, complete committed-state emission, actual message capture, model metadata and billing. An event-count/final-snapshot assertion cannot prove that a trusted connector truthfully emitted every event; hashes are integrity checks, not authenticated proof of an experiment.

The [handoff guide](evaluation_guide.md) gives the one-command offline workflow, exact later live command and approval/freeze procedure. Suggested commits separate tooling, scenarios/attack, independent grading, runner/evidence utilities and documentation. Nothing has been staged, committed or pushed by the assistant. Human review remains pending.

## 2026-09-28 — Native integration and functional organization

PROMPT-005 authorizes integration, functional naming and local commits. PROMPT-006 extends scope to the missing baseline agent adapter. PROMPT-007 delegates provider/model selection. All three user messages and replies are preserved in the local prompt history with capture timestamps. The September 22 message was not saved, as requested.

### Repository preservation and naming

Fetched `origin` and inspected `origin/simulator` at `78c8e1c`. It contains Ahmed's WP-02/WP-03 commits and descends from the latest main branch; it contains no agent adapter. Work proceeds on local `evaluation-integration` based on that history. A checksummed backup of all 41 original local source/document files was created at `artifacts/local/integration-backup` before switching branches; original implementation artifacts retain their bytes. Existing author history and Git configuration were preserved.

Active prose uses Simon and Ahmed. Functional names replace the provisional calendar-based paths: `scripts/evaluate.py`, `configs/evaluation/`, `scenarios/development/`, `fixtures/evaluation/`, `docs/evaluation_interface.md` and `docs/evaluation_guide.md`. Tests are organized by unit, integration and security behavior. The existing locally ignored task notes were renamed `docs/baseline_tasks.md`, with the ignore rule updated. Historical user prompts, source contract and old evidence remain unchanged.

### Integration changes

Scenarios, payload mutation and independent grading now use native snapshots with state version, millisecond time and every device field; native action records and operation permissions; and gateway-issued observations. The grader inspects action, environment and clock history. Sensor reads require actual gateway read receipts and are not fabricated committed actions. Payload attacks change only the designated message field, preserving trusted envelopes and canonical facts.

The replay backend executes recorded proposals against the actual simulator. A separate bounded agent accepts provider responses, parses actions, receives limited execution feedback and stops at the configured bounds. The trusted execution backend holds mutation capabilities; the model and agent do not receive them or hidden grading labels. The baseline prompt describes task/action formatting without adding the later prompt-defended condition's warning. Its version remains a draft for protocol review.

The provider connector targets OpenAI `gpt-4.1-mini-2025-04-14` using Responses and a separately logged exact input-token-count preflight. This starting choice favors a fixed, documented non-reasoning model for a small typed-action loop; it is not a measured claim that this model is best for the research outcome. Official model/API documentation was consulted through the OpenAI Docs skill. The published rate calculation is labelled estimated cost; provider token counts are actual reported usage. Model date identifies the snapshot date, and each attempt separately records its execution timestamps. No real provider call or key retrieval was used in verification.

A Python 3.14 runtime check exposed an existing parser test's dependence on the interpreter recursion limit. The minimal runtime correction bounds JSON nesting explicitly to 16 containers while respecting escaped strings. The existing invalid-deep-input test and an additional string-boundary regression verify that behavior. Other native runtime implementation files remain preserved.

Review also corrected native request-field logging, malformed provider-response accounting, foreign-currency handling, exact-step termination and incomplete live-call accounting. A timed-out live worker can have incurred an unreported charge: the runner retains known subtotals while marking totals incomplete. Known usage is persisted before potentially malformed provider-visible messages. These safeguards were exercised with offline test doubles, not paid calls.

### Research status

The original September 25 baseline checkpoint has passed. No frozen live gate result exists, so all three live criteria remain unassessable. Provider/model selection and implementation/commit authorization do not supply credentials, a spending cap, joint semantic/protocol acceptance or freeze approval. The budget remains zero. The team must record its gate/fallback disposition before later enforcement work; this integration does not silently change the schedule or select a reduced study.

Source/data, tests, configuration, dependency pins, placeholder-only environment example and tracked guides are the reviewable outputs. Prompt history and existing private planning notes retain their local ignore choices. No credentials, environments, caches, backups or generated run bundles are included in commits.

### Final integration verification and commits

On Python 3.14.6, the combined suite passed **344 tests and 95 subtests** in 12.17 seconds. Ruff lint and formatting passed for 55 Python files; strict mypy passed for all 33 source files. The suite includes Ahmed's native runtime checks and the scenario, mutation, grader, accounting, runner, freeze, audit, agent and 56 mocked OpenAI transport tests. No network/provider calls are made by those tests.

```sh
.venv/bin/python -m pytest -q
.venv/bin/ruff check src tests scripts examples
.venv/bin/ruff format --check src tests scripts examples
.venv/bin/mypy
git diff --check
```

The complete commands below were also executed and their evidence audits passed, each retaining 33 runs and 170 hashed files:

```sh
.venv/bin/python scripts/evaluate.py offline --output artifacts/local/evaluation/offline-verified
.venv/bin/python scripts/evaluate.py verify-evidence artifacts/local/evaluation/offline-verified
.venv/bin/python scripts/evaluate.py simulator-replay --output artifacts/local/evaluation/replay-verified
.venv/bin/python scripts/evaluate.py verify-evidence artifacts/local/evaluation/replay-verified
.venv/bin/python scripts/evaluate.py baseline --output artifacts/local/evaluation/baseline-verified
.venv/bin/python scripts/evaluate.py verify-evidence artifacts/local/evaluation/baseline-verified
```

Each mode produced the intended 30/30 clean completions and 3/3 matched authored action changes, including three unsafe attacked runs. These are deterministic fixture expectations, not empirical language-model results. All live gate criteria remained unassessable. The full test output is retained at `artifacts/local/integration-backup/combined-tests-final.txt`; earlier checks and the pre-integration source backup remain available locally.

The final timeout regression verifies that the exact converted provider request is durably recorded through the runner before a simulated blocked network operation is killed. The API implementation uses that same acknowledged event path before count and generation requests. This is offline evidence of the logging behavior; real provider availability, latency and account access remain untested.

Authorized implementation commits on `evaluation-integration`:

| Commit | Purpose |
| --- | --- |
| `c3a2c75` | Portable action JSON nesting bound and regression |
| `307735e` | Pinned offline verification tools |
| `6320ae2` | Native scenarios and bounded payload attacks |
| `a815d38` | Independent full-trace grading |
| `a4b5132` | Bounded baseline adapter, native execution and OpenAI client |
| `c38036b` | Isolated runner, durable evidence, summaries and gate utilities |
| Documentation commit containing this entry | Functional organization, current interfaces, status and verification record |

The branch preserves `origin/simulator` and `origin/main` as ancestors. No remote push, model spend, official freeze or live gate was performed. The configured human Git identity was used without modification; AI assistance is disclosed here without an AI co-author trailer.
