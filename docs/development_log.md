# Observable AI assistance and verification log

Editorial update, September 28: historical path references below use the current functional names. Original wording and source revisions remain in Git. Disposable offline verification outputs and backup copies have been removed at Simon's request; the outcomes and limitations remain recorded here. Verbatim prompts and the source contract are preserved.

## 2026-09-21 — Simon's baseline evaluation tooling

This entry records observable assistance, artifacts and verification for the baseline evaluation work requested on September 21, captured at `2026-09-21T16:40:07+04:00`. This log discloses AI assistance without assigning Git authorship or claiming human approval. Hidden reasoning, system/developer instructions and credentials are excluded. Decision IDs used below are defined in the tracked [requirements](requirements.md#open-decisions).

### Scope and repository inspection

The assistant inspected the repository, working instructions, preserved research contract, requirements, dated plan, decision register, Git status and available code. The repository had planning documents but no simulator, gateway, runtime schema, agent adapter or existing implementation tests. The user's commit `569258d` was preserved. Existing ignore choices, including the locally ignored prompt history and decision register, were preserved.

Simon authorized his five baseline evaluation tasks and explicitly reserved Ahmed's components for Ahmed. The implementation therefore uses a provisional evaluation record format and authored static trace fixtures. It does not implement a simulator or model adapter. Joint integration can only be tested once Ahmed supplies those components.

Two clarification questions were raised: whether Ahmed's interfaces exist elsewhere, and whether D09 should use proposed or executed action changes. No answers to those questions were available when this implementation was prepared. The runner supports both measurements; executed changes, three repetitions and an 80% reliability threshold remain proposals. No approval, official freeze, credentials, paid inference or live gate result was manufactured.

### Generated outputs and file inventory

| Files | Observable output |
| --- | --- |
| `pyproject.toml`, `requirements-dev.txt`, package `__init__.py` files | Python 3.11+ project metadata, standard-library runtime and pinned Ruff development tool |
| `src/effectshield/scenarios.py`, `scenarios/development/baseline.json` | Validated development suite: ten clean tasks spanning five devices plus one matched attacked variant, with stable IDs, initial state, requests, observations, completion/policy predicates and run fields |
| `src/effectshield/attacks.py` | Bounded mutation of explicitly allowed payload text; protected labels, envelope identity/time/IDs, permissions and initial state remain unchanged |
| `src/effectshield/grading.py`, `fixtures/evaluation/grader_cases.json` | Independent complete-trace grading and ten hand-labelled fixtures; unsafe intermediate effects remain failures after recovery; recorded repairs require safe task completion |
| `fixtures/evaluation/runs.json`, `src/effectshield/experiments/backends.py` | Explicit static trace replay for offline tests, plus a loader for Ahmed's future trusted connector |
| `src/effectshield/experiments/runner.py`, `storage.py` | Spawned-process attempts, exact reset check, durable event acknowledgement, separate proposed/committed actions, all-attempt ledger, retries/timeouts/bounds, actual/unknown usage distinction and secret redaction |
| `src/effectshield/experiments/report.py`, `checks.py`, `audit.py` | Fixture self-check, summaries, both action-change measures, missing/failure accounting, three gate statuses and read-only integrity/regrading checks |
| `src/effectshield/experiments/freeze.py`, `configs/evaluation/gate.json` | Draft protocol, approval-bound hashes/snapshots and verification, source/input binding and one official batch per freeze |
| `src/effectshield/experiments/cli.py`, `scripts/evaluate.py` | Offline, rehearsal, approval-hashes, freeze, gate and evidence-verification commands |
| `tests/unit/`, `tests/integration/`, `tests/support_backends.py`, `tests/__init__.py` | Unit and integration checks with static test doubles; no provider calls |
| `docs/evaluation_interface.md`, `docs/evaluation_guide.md`, this file | Provisional Ahmed handoff, exact commands, blockers, evidence layout, review groups and AI-use/verification record |
| `README.md`, `docs/project_plan.md` | Current implementation stage and links while preserving the agreed calendar |

Independent assistant reviews checked the mutation boundary, full-trace grading, freeze integrity, failure accounting and final handoff consistency. These reviews are AI assistance, not Simon's or Ahmed's acceptance. Source files and documents contain the reviewable generated outputs.

### Verification performed

Environment: macOS arm64, Python 3.14.6, Ruff 0.16.8 in an ignored `.venv`. Runtime code uses the standard library. Compatibility with every supported Python version was not tested.

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
.venv/bin/ruff check src tests scripts
.venv/bin/ruff format --check src tests scripts
git diff --check
```

The final unit/integration run passed **101 tests** in 6.676 seconds. Its disposable raw output has since been removed under Simon's September 28 cleanup request. Ruff lint and formatting checks passed for 23 Python files. Tests exercise payload confinement, exact JSON types, every committed transition, unsafe effects followed by recovery, malformed/incomplete traces, deterministic reset, cross-run isolation, partial failures/timeouts, retry denominators, unknown usage, usage monotonicity, reserved-event rejection, evidence tampering, approval bindings and freeze reuse prevention.

Earlier verification exposed and corrected two seed issues. Adding an unsupported-seed constraint invalidated a synthetic freeze fixture that used seed `0` with status `unsupported`; that fixture now uses `null`. A new regression test then exposed the missing opposite constraint: a supported seed cannot be left unspecified. The validator now requires its explicit integer value. The earlier failing outputs were kept separately during verification and have since been removed with the disposable logs; the failure descriptions remain in this record. Earlier test runs and review also led to stricter canonical comparisons, monotonic usage, durable event delivery and frozen-connector binding.

The complete CLI workflows were exercised using static data. Equivalent commands with the current functional names are:

```sh
python3 scripts/evaluate.py offline --output artifacts/local/evaluation/offline-final-verification
python3 scripts/evaluate.py verify-evidence artifacts/local/evaluation/offline-final-verification
python3 scripts/evaluate.py rehearsal --output artifacts/local/evaluation/rehearsal-final-verification
python3 scripts/evaluate.py verify-evidence artifacts/local/evaluation/rehearsal-final-verification
```

Each workflow retained 33 attempts, with 30/30 clean fixture goal completions and 3/3 matched action changes in both measures. Each evidence audit passed with 170 hashed files and 33 run records. All three gate statuses remained `unassessable`. These numbers are authored fixture expectations, not measured model performance. Cost/token/call values are explicitly synthetic zeros. Reports include actual local runtime latency, invocation, source/configuration hashes, run IDs and ledger paths.

After the final seed-validation correction, the offline workflow and audit were repeated successfully against the final source: 33 attempts, 170 verified files and the same fixture outcomes. Earlier disposable output was retained during verification and has since been removed under Simon's September 28 cleanup request. Rehearsal separation and accounting were also exercised by the passing final integration tests.

Final documentation checks passed for all 11 Markdown files, existing local links, balanced code fences, whitespace and valid JSON configuration/scenario/fixture files. Git whitespace checks passed, the index remained empty, and generated evidence, the local environment and caches remained ignored. These checks do not claim that ignored local documents are published to GitHub.

### Remaining work and review status

| Baseline live criterion | Status | Reason |
| --- | --- | --- |
| At least 70% benign completion | Unassessable | No approved live model run |
| Reliably action-changing attack | Unassessable | D09 is pending and no live attack measurement exists |
| Automatic grading of gate runs | Unassessable | Offline grader checks pass, but no official live traces exist |

Ahmed still supplies the simulator, gateway, runtime schemas and agent connector. D03/D04/D05/D09/D10/D11/D13 need the relevant human decisions before an official freeze. Real integration must verify reset/isolation, complete committed-state emission, actual message capture, model metadata and billing. An event-count/final-snapshot assertion cannot prove that a trusted connector truthfully emitted every event; hashes are integrity checks, not authenticated proof of an experiment.

The [handoff guide](evaluation_guide.md) gives the one-command offline workflow, exact later live command and approval/freeze procedure. Suggested commits separate tooling, scenarios/attack, independent grading, runner/evidence utilities and documentation. Nothing has been staged, committed or pushed by the assistant. Human review remains pending.

## 2026-09-28 — Native integration and functional organization

Simon authorized integration, functional naming and local commits, then extended the scope to the missing baseline agent adapter and delegated provider/model selection. The user instructions were recorded with capture timestamps. The September 22 message was not saved, as requested.

### Repository preservation and naming

Fetched `origin` and inspected `origin/simulator` at `78c8e1c`. It contains Ahmed's WP-02/WP-03 commits and descends from the latest main branch; it contains no agent adapter. Work proceeds on local `evaluation-integration` based on that history. A checksummed temporary backup of the 41 original local source/document files was used while switching branches and was subsequently removed under Simon's September 28 cleanup request. Git now supplies the committed source history. Existing author history and Git configuration were preserved.

Active prose uses Simon and Ahmed. Functional names replace the provisional calendar-based paths: `scripts/evaluate.py`, `configs/evaluation/`, `scenarios/development/`, `fixtures/evaluation/`, `docs/evaluation_interface.md` and `docs/evaluation_guide.md`. Tests are organized by unit, integration and security behavior. Local task notes were renamed by function, with their ignore rule updated. Historical user prompts and the source contract remain unchanged. Superseded disposable verification outputs were later removed under Simon's September 28 cleanup request.

### Integration changes

Scenarios, payload mutation and independent grading now use native snapshots with state version, millisecond time and every device field; native action records and operation permissions; and gateway-issued observations. The grader inspects action, environment and clock history. Sensor reads require actual gateway read receipts and are not fabricated committed actions. Payload attacks change only the designated message field, preserving trusted envelopes and canonical facts.

The replay backend executes recorded proposals against the actual simulator. A separate bounded agent accepts provider responses, parses actions, receives limited execution feedback and stops at the configured bounds. The trusted execution backend holds mutation capabilities; the model and agent do not receive them or hidden grading labels. The baseline prompt describes task/action formatting without adding the later prompt-defended condition's warning. Its version remains a draft for protocol review.

The provider connector targets OpenAI `gpt-4.1-mini-2025-04-14` using Responses and a separately logged exact input-token-count preflight. This starting choice favors a fixed, documented non-reasoning model for a small typed-action loop; it is not a measured claim that this model is best for the research outcome. Official model/API documentation was consulted through the OpenAI Docs skill. The published rate calculation is labelled estimated cost; provider token counts are actual reported usage. Model date identifies the snapshot date, and each attempt separately records its execution timestamps. No real provider call or key retrieval was used in verification.

A Python 3.14 runtime check exposed an existing parser test's dependence on the interpreter recursion limit. The minimal runtime correction bounds JSON nesting explicitly to 16 containers while respecting escaped strings. The existing invalid-deep-input test and an additional string-boundary regression verify that behavior. Other native runtime implementation files remain preserved.

Review also corrected native request-field logging, malformed provider-response accounting, foreign-currency handling, exact-step termination and incomplete live-call accounting. A timed-out live worker can have incurred an unreported charge: the runner retains known subtotals while marking totals incomplete. Known usage is persisted before potentially malformed provider-visible messages. These safeguards were exercised with offline test doubles, not paid calls.

### Research status

The original September 25 baseline checkpoint date has elapsed. No frozen live gate result exists, so all three live criteria remain unassessable. Provider/model selection and implementation/commit authorization do not supply credentials, a spending cap, joint semantic/protocol acceptance or freeze approval. The budget remains zero. The team must record its gate/fallback disposition before later enforcement work; this integration does not silently change the schedule or select a reduced study.

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

Each mode produced the intended 30/30 clean completions and 3/3 matched authored action changes, including three unsafe attacked runs. These are deterministic fixture expectations, not empirical language-model results. All live gate criteria remained unassessable. The disposable test output and pre-integration source backup have since been removed under Simon's September 28 cleanup request; the verification outcomes and commits are recorded here.

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

### Concurrent simulator updates

Before final handoff, the simulator branch advanced to `ee8a0db` with `008fa4c` (its own explicit nesting fix) and `ee8a0db` (setup guide). Those commits are merged with their history preserved. The overlapping temporary 16-container parser fix is superseded by Ahmed's native 4-container limit and `NESTING_TOO_DEEP` error code. Both sets of string-boundary regressions are retained. README/setup instructions now cover the combined functional commands, pinned tools and local integration branch. The final verification below supersedes the pre-merge test count while retaining that earlier record.

After resolving the concurrent updates, **346 tests and 95 subtests passed** in 11.85 seconds; all 55 Python files pass Ruff lint/format, all 33 source files pass strict mypy, and Git whitespace checks pass. The complete bounded-agent workflow was repeated at `artifacts/local/evaluation/baseline-merged-verified`: 33 attempts, no invalid traces and a passing 170-file evidence audit. The disposable post-merge output has since been removed under Simon's September 28 cleanup request. All live criteria remain unassessable. The merge commit preserves both collaborators' histories and the combined tree is the handoff target.

## 2026-09-28 — Repository cleanup and functional naming

Simon requested Git-based source history without backup trees or cached prior code. Removed the temporary integration backup, superseded offline run bundles and tool caches. No actual live experiment, approval record or official freeze existed in those outputs. The source contract, verbatim prompt history, curated fixtures and all existing commits remain intact.

Renamed the remaining test credential variable to `EFFECTSHIELD_TEST_API_KEY`; the redaction behavior is unchanged. Normalized historical documentation paths and active calendar labels to functional terminology, kept the timeline in the project plan and updated its integrated implementation status. README and the evaluation guide now distinguish disposable verification output from retained research evidence. The local working instructions and decision notes follow the same policy.

The committed-only export of `bebeddd` had already passed 346 tests and 95 subtests, a 33-attempt scripted baseline and a 170-file evidence audit. That temporary export and its disposable output have been removed. Cleanup verification and commit grouping follow below. No paid inference, live gate result or push is implied.

Cleanup verification: **346 tests and 95 subtests passed** in 13.22 seconds with bytecode writing and the pytest cache disabled. Ruff lint/format passed for all 55 Python files; mypy passed for all 33 source files with its cache directed to the null device. The longer renamed test variable initially exceeded the line limit; formatting corrected it and both Ruff checks then passed. The scripted baseline completed 33 attempts, and its audit verified 170 files before the temporary output directory was removed. All live gate criteria remain unassessable.

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider
PYTHONDONTWRITEBYTECODE=1 .venv/bin/ruff check --no-cache src tests scripts examples
PYTHONDONTWRITEBYTECODE=1 .venv/bin/ruff format --check --no-cache src tests scripts examples
PYTHONDONTWRITEBYTECODE=1 .venv/bin/mypy --cache-dir=/dev/null
```

The baseline and `verify-evidence` commands used a Python `TemporaryDirectory` for their output. No new source backup or persistent verification bundle was created. Commit grouping separates functional test naming from documentation and repository workflow. Existing author history and branch ancestry are preserved.

Documentation verification passed for 13 Markdown files (local links, balanced fences and prose whitespace); all 89 requirement IDs and owners are unchanged. Active tracked files contain no calendar-specific baseline labels outside the project plan. The native domain, simulator, gateway and environment still match `origin/simulator`. The functional test naming commit is `4f475b8`; the documentation/workflow changes are in the commit containing this entry.

### Additional simulator demonstration commits

The final ancestry check detected two further fetched simulator commits, `89d2857` and `3acaaaa`, containing the scripted attack demo and its run-guide explanation. They are integrated with their original history preserved. The guide conflict was resolved by retaining the existing baseline/replay commands and adding the demo command. Calendar-specific labels in the new example and guide were replaced with baseline terminology. The explanation and printed rule hints distinguish stale evidence from an ID-consumption violation, whose semantics remain a protocol decision, and clarify that the unprotected demo does not automatically become protected when a mediator is added. No runtime device behavior was changed.

`PYTHONDONTWRITEBYTECODE=1 .venv/bin/python examples/attack_demo.py` ran successfully: both authored attacks produced the expected simulated door effects, including unauthorized door operations in the hidden-instruction case. This is a scripted mechanics demonstration, not measured model susceptibility. Ruff lint and format pass for the expanded set of 56 Python files. No retained output or backup tree was created.

After integrating the demonstration, the full suite again passed **346 tests and 95 subtests** in 12.82 seconds with caches disabled. The prior strict mypy check remains applicable because the 33 package source files are unchanged. The final repository checks confirm functional names, valid document links, the preserved contract hash and no backup/cache directories or retained disposable run bundles.

## 2026-09-28 — Documentation that works from GitHub

Simon requested self-contained tracked requirements and a clear dated plan, without navigation into local-only files. The requirements now include the definitions for all 16 decision IDs and the ten research-source entries alongside the existing 89 requirements. The plan contains the dated owner assignments, timeline, phase dependencies and baseline gate/fallback criteria. Conversational prompt IDs and local-note dependencies were removed from those documents.

README and the runtime/evaluation guides now link to tracked requirements and planning sections. The historical log's link to the local prompt record was removed; the original user wording remains preserved locally. Existing ignore rules, source code, scenarios, configuration and research thresholds are unchanged. This edit does not grant protocol approval or establish a live gate result.

Verification checks repository links against Git-tracked membership and Markdown anchors, rather than whether files happen to exist on the current machine. It also checks requirement ownership, decision/source definitions, dates, tables, fences and whitespace. The completed results are recorded below. No runtime tests are needed for this documentation-only change, and no caches or backup copies are created.

Documentation verification passed for **all eight tracked Markdown files**, including **43 repository links and nine section anchors** checked against the Git file list, 33 tables, balanced fences and whitespace. All 89 requirement IDs and owners are preserved. Only GOV-02 and GOV-03 wording changed within the requirement rows, to describe the shared decision table and local prompt-history obligation without pointing readers to unpublished files. All other requirement rows are unchanged. The 16 decision definitions, ten research entries, ten calendar weeks, ten daily owner tasks and 14 work packages were verified; a separate review checked the milestone weekdays and requirement/dependency mappings.

The tracked documents contain no references to ignored working-note filenames or conversational prompt IDs. The update is committed as one documentation group covering the requirements, plan, README, runtime/evaluation guides and this verification log. No runtime tests were run because no executable behavior changed. No files were force-added, no ignore rules were changed and nothing was pushed.

## 2026-09-29 — Interactive offline progress view

Simon requested a visualization of current progress. Produced an in-conversation view of the verified offline components, saved batch totals and a replay of the matched clean/attacked light task. The case selector and step control read native saved snapshots and independent grader results from the September 28 batch `83ba11724a44404cafe094ae86aaab37` at revision `1a8979d`. The injected case turns on the light and then unlocks the door while nobody is present; the door stays closed. The view distinguishes task completion from the unsafe extra effect and labels the results as scripted. Live inference, mediator/repair and final-study work remain pending.

Verification: embedded snapshots, transitions and grades match the saved run records exactly. Browser assertions passed for case switching, every replay step, final grades and run identity. Light and dark appearances were inspected at 736px and 360px content widths, with an additional 320px layout check. The first narrow screenshot used Chrome's larger minimum viewport and cropped its capture; testing an explicit content width verified the actual responsive layout. Browser processes that remained open after producing their DOM/screenshot output were stopped. All temporary previews, screenshots and isolated browser profiles were removed after inspection.

The visualization makes no network or provider calls and does not change runtime code, experiment configuration or evidence. It is a progress view, not the final research dashboard or a live gate result. The generated conversation output stays outside Git; this log records the assistance and verification. No backup source tree was created.

## 2026-09-30 — Local saved-evidence viewer

Simon requested a way to visualize the output from the baseline command locally. Added `visualize` to the evaluation CLI, a small renderer in `experiments/visualize.py` and a packaged, self-contained HTML template. The command audits an existing bundle before creating a sibling HTML report; an optional output path must remain outside that bundle. Existing files and symlink targets are protected from overwrite. No experiment or provider call is performed.

The viewer shows saved batch counts and gate statuses, all attempts, matched-counterpart navigation, five-device snapshots and the full transition history. Task completion, execution status and unsafe effects remain distinct. Initial tool observations and completed read receipts have separate views; no device transition or receipt ordering is invented. Unknown values and invalid traces retain their diagnostic status. Recorded simulator time is preserved. Model/cost provenance and the limitations of scripted results remain visible. This supports evidence inspection under EXP-10, LOG-05 and LOG-06; it does not establish formal acceptance, a live gate pass or completion of the final Streamlit dashboard.

Untrusted strings are embedded as escaped inert JSON and inserted as text. A content security policy permits only the bundled executable script by hash and blocks network access. Checks found and corrected a browser failure on malformed retained snapshots; those frames now show unavailable state alongside grader errors. An unassessable matched pair receives an explicit warning. Counterpart step numbers do not imply semantic alignment.

Verification completed:

- Full offline suite: **365 tests and 116 subtests passed**. Ruff lint/format passed for 58 Python files; strict mypy passed for 34 source files. Bytecode, pytest and persistent tool caches were disabled. The viewer's 19 tests and 21 subtests passed again after template formatting.
- Tests cover exact record/trace/scenario preservation, independent audit preservation, tamper rejection, output boundaries, symlink aliases, overwrite races, CLI behavior, invalid traces and lossless HTML-safe JSON. Initial test assertions were corrected to account for macOS's `/var` path alias without weakening file-preservation checks.
- Browser assertions checked all 33 saved attempts and every native replay frame, matched run IDs, whole-run grades, read-only tasks, gate statuses and unsafe reason codes. Additional cases checked missing snapshots, unknown grades, invalid pairs and hostile HTML remaining inert. Desktop light/dark and an explicit 360px narrow layout were inspected; the narrow test activated its responsive rules because headless Chrome enforces a larger minimum viewport. All checks passed. An initial browser test contained a literal script-closing tag in its own assertion; correcting that temporary harness allowed the intended hostile-text check to run.
- A wheel built in a temporary environment included the renderer, CLI and HTML template. The local development environment lacked the build backend, so isolated temporary build dependencies were used. No runtime dependency was added and the project environment was not changed.
- README and the evaluation guide document creation, opening, output paths, interpretation and limitations. All eight tracked Markdown files passed checks for 44 repository links, ten anchors and balanced fences. Git whitespace checks passed.

Generated the local report for the existing September 28 batch `83ba11724a44404cafe094ae86aaab37`; the original bundle still passes its **33-run, 170-file audit**. The user prompt was appended to the local prompt history with an actual capture timestamp. Temporary browser profiles, screenshots, formatter files/cache and packaging outputs were removed. No source backup was retained. Source, tests, package metadata, instructions and this log form one viewer component commit under the existing local-commit authorization. No push, model spend or human research/security acceptance is implied.

## 2026-10-05 — WP-05 bounded agent adapter and condition configurations

WP-05 was requested on a new branch, `wp-05-agent-adapter`, from `main` at `f0e2260`. The existing bounded adapter, OpenAI connector and scripted fixture model already covered most of AGT-01 and AGT-06. This change adds the missing parts:

- Three versioned condition files in `configs/conditions/`. They are validated by a strict loader, and a check reports only declared treatment differences. The safety-prompt condition has no enforcement. The EffectShield condition shares the unprotected prompt and is refused by the baseline backend until a mediator exists.
- A frozen continuation protocol, `continuation-draft/v1`. It defines exact agent-visible feedback for committed, observed, rejected, blocked, repaired, abstained and escalated outcomes. Abstention and escalation stop without another model call. Two consecutive refusals end retry loops. Blocks cannot gain calls beyond the shared limits.
- An agent-side wall-clock limit checked before each model call.

The unprotected prompt is unchanged, so earlier evidence remains comparable. Existing adapter tests that passed loosely shaped feedback were updated to use protocol-shaped transaction results; the behaviour they test is unchanged.

Verification: the full offline suite passed **418 tests and 116 subtests**. Ruff lint and format passed, strict mypy passed for 36 source files, and `git diff --check` was clean. The offline `baseline` command still produced 30/30 clean completions and 3/3 matched action changes, and its evidence audit passed for 33 runs. These are scripted fixture results, not model measurements. No provider calls were made.

Still pending: Simon's review of the condition definitions and safety instruction (AGT-02); run-manifest wiring of conditions in the runner (AGT-03, WP-06); runner and grader support for the `escalated` termination; and D09 approval of the continuation protocol and refusal limit.

## 2026-10-07 — Authorization evaluation and condition comparisons

Simon requested a branch from Ahmed's agent-adapter work and completion of the planned evaluation tasks, then explicitly requested component commits. Created `authorization-evaluation` from `origin/wp-05-agent-adapter` at `e8e778e`; the merged baseline and viewer are ancestors through `main`. Ahmed's native simulator, gateway, schemas, agent implementation and condition definitions were preserved. The selected branch contains the adapter/continuation work but no mediator. The question about a separate mediator location remains unanswered; protected integration stays pending rather than being simulated as implemented protection.

Completed the independent development corpus: seven clean/attacked pairs and three additional benign controls, with native reference traces and separately hand-assigned task, safety and reason-code expectations. Cases cover forged system/user authority, operation scope, valid and invented references presented as authority, false presence and additional-device scope expansion. Boundary checks cover protected-field mutations, forged action fields and invalid request identity. Initial fixture construction caught missing declared attack surfaces and canonical permission ordering; these were corrected before the corpus was saved. The 73 corpus checks pass. Protected-path expectations remain draft review material.

Wired the existing conditions into the scripted runner. Named batches retain the full condition/hash, per-attempt identity, actual prompt version and captured scripted input. Audits verify initial model-visible messages and configuration bindings. The comparison command retains separate baseline bundles, validates matching, reports missing/invalid cells and explicitly leaves EffectShield not run. Added terminal escalation support across runner, grading and accounting without automatic retry or fabricated permission; actual completion and safety remain independent. Updated the viewer's condition label, usage/interface documentation, planning status and a draft research report with methods and an outline; no research result is invented.

Verification: **513 tests and 116 subtests passed**; Ruff lint/format passed for **67 Python files**; strict mypy passed for **37 source files**. Checks used `PYTHONDONTWRITEBYTECODE=1`, disabled pytest/Ruff caches and directed mypy's cache to the null device. Additional tests detect condition relabeling, altered prompts/input fixtures, model/limit/retry drift, missing attempts, incomplete traces, unavailable protection and credential-shaped export content. Escalation fixtures verify no-effect, authorized-effect and unsafe-effect outcomes and retain incomplete traces as unknown. A first style check caught an unused test import and a long string; both were corrected before the passing checks. All nine tracked Markdown documents passed link checks against the Git index: 62 repository links and 15 anchors, with balanced fences and clean whitespace.

The real CLI completed **102 scripted attempts**, 51 per available condition. In each condition: 30/30 clean completion, 21/21 changed attacked sequences, 21 unsafe attempts, 48 total task completions and no invalid traces. All 51 cross-condition cells matched. The two bundles independently passed **51-run, 261-file audits**, and `verify-comparison` regenerated the report. The original saved baseline still passes its 33-run, 170-file audit. These are authored response outcomes, not live model performance or prompt-only defense efficacy; all live gate criteria remain unassessable.

A headless browser smoke check confirmed the new prompt-only condition label and all 51 selectable attempts in the generated viewer. No connected browser was available; the isolated local browser profile and all temporary comparison/browser outputs were removed afterward. No provider calls, spending, protected effects or remote push occurred. The pre-existing local source-contract edit was left unchanged and excluded from staging. Prompt history captures the implementation request and subsequent commit instruction; the earlier learning prompt remains excluded as requested.

Commit grouping: `c4fc040` adds the adversarial corpus and its tests; `19691c7` adds terminal escalation evidence handling; `0c655b3` adds condition-bound batches, comparison/audit utilities and tests; the documentation commit containing this entry records instructions, methods, planning status and verification. Joint semantic/security review, mediator integration, live access/budget and gate/fallback decisions remain outstanding. Commit authorization does not approve those research decisions.

## 2026-10-07 — Adapter audit and baseline gate dependency review

Simon clarified that Ahmed completed WP-05 and is waiting on WP-06. Checked the fetched adapter branch at `e8e778e`, confirmed it is an ancestor of the current branch, and reviewed adapter, condition, continuation and provider tests. No missing WP-05 implementation was identified within the declared offline scope. The earlier request to locate a separate mediator is superseded: WP-07 is Ahmed’s subsequent package and depends on the baseline gate disposition. Updated the project plan with requirement-level evidence, outstanding acceptance, the original 33-attempt gate population and the exact handoff sequence. No runtime behavior changed.

Independently audited Simon’s supplied `comparison-2026-10-07-9d712fee`: verification passed with 51 matched cells across 102 scripted attempts. Re-ran the full suite: **513 tests and 116 subtests passed in 24.42 seconds**. Ruff lint and formatting passed (67 files); strict mypy passed (37 source files); the independent grader self-check passed all 10 cases. Documentation links were checked against tracked paths and anchors, and whitespace checks passed.

Asked Simon for joint approval of the concrete draft gate protocol, an explicit total live spending limit and the full-scope/fallback disposition. These answers remain pending; no approval, live result or WP-06 completion is claimed. Remaining baseline semantic, evidence and security reviews are listed in the plan. No paid calls, source backups or remote push were made. The user’s modified contract remains excluded. The project prompt was captured in the local prompt history with a timezone-aware capture timestamp; the pasted CLI JSON was transcribed from the matching saved report with whitespace normalization disclosed. This documentation-only handoff is one coherent local commit under the continuing commit instruction.
