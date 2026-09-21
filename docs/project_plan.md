# EffectShield phased project plan

Updated 2026-09-21 from Simon's calendar clarification in PROMPT-002 and follow-up in PROMPT-003. **We are in Week 4, Monday September 21 to Friday September 25, 2026.** The submission window is Week 13, **November 23–27**; its exact submission day/time remains unconfirmed. Simon agreed to keep that window and **Friday November 20** as the internal completion date. All dates use Asia/Dubai.

Aim for a complete deliverable candidate by **Friday November 6 (Week 10)**, joint review by **Friday November 13 (Week 11)**, and all corrections and internal sign-off by **Friday November 20 (Week 12)**. Week 13 is reserved for submission. The original contract's Weeks 14–15 delivery schedule is retained in the source document as history; the user's new Week 13 deadline and Weeks 10–12 completion goal control this working plan. Preserve all research deliverables and acceptance criteria while moving the work earlier.

The repository currently contains requirements documentation and no implementation. This is a demanding recovery week with two parallel work streams; the first dependency is agreement on the minimal interfaces and gate protocol. Simon has asked to prioritize completing the week's tasks and said both will spend the time needed, so no hourly availability limit is assumed. This plan sets work and verification targets, not a claim that they have been completed. Implementation still proceeds one selected task at a time with review before commits.

## Calendar and weekly outcomes

Week 1 derives to August 31–September 4 by counting back from the supplied Week 4 anchor. Earlier weeks are not marked complete. Detailed daily assignments are in [Week 4 tasks](week_04_tasks.md).

| Week | Monday–Friday in 2026 | Ahmed's delivery | Simon's delivery | Joint checkpoint |
| --- | --- | --- | --- | --- |
| 4 | September 21–25 | Typed interfaces, five-device simulator, trusted gateway, bounded baseline agent adapter and tests | Development tasks, one attack, independent grader, run ledger and baseline gate evidence | Friday September 25: reproducible benign completion at least 70%, reliable action-changing attack and automatic grading |
| 5 | September 28–October 2 | Schema, device authorization and instruction-provenance enforcement | Adversarial authorization/provenance cases, baseline configurations and outcome fixtures | Review the first protection path end to end; settle D05 before rule 3 implementation |
| 6 | October 5–9 | Freshness/replay checks; begin door, thermostat and sequence enforcement | Stale/replayed-observation cases, independent expected outcomes and runner accounting | Verify TTL/ID boundaries and state interactions; settle D06–D07 before enforcement |
| 7 | October 12–16 | Finish all eight rules, bounded task-preserving repair and integrated feedback | Repair/sequence fixtures, complete development coverage and prepare held-out pilot | Feature-complete target October 16; applicable rule and integration checks pass |
| 8 | October 19–23 | Resolve pilot defects and verify rule/repair behavior | Run held-out pilot; finalize 24-task test manifest, grader, metrics, analysis fixtures and run budget | Freeze final protocol by October 23 only after pilot and correctness gates pass |
| 9 | October 26–30 | Support frozen runs; investigate implementation faults through recorded protocol deviations | Execute main experiments and trace ablations; retain traces, grades, costs and run ledger | Check run completeness and artifact integrity; no tuning on final results |
| 10 | November 2–6 | Independently replay results and review failure explanations; contribute report/demo | Finish analysis/CIs, complete report draft, Streamlit dashboard and five-minute demo candidate | Stretch target: complete artifact candidate by November 6, subject to all evidence gates |
| 11 | November 9–13 | Independently verify installation/replay; review security claims and rehearse demo | Reconcile report/tables/dashboard, package evidence and rehearse demo | Review-ready package by November 13; both record corrections needed |
| 12 | November 16–20 | Resolve reviewed defects and verify affected behavior | Complete approved corrections, regenerate affected artifacts and check submission package | Internal completion and sign-off by Friday November 20 |
| 13 | November 23–27 | Support submission and presentation as required | Coordinate submission of the reviewed artifact/report | External deadline window only; exact submission date/time pending |

Draft methods, experiment notes and the report outline alongside development from Week 5, using reviewed facts and leaving results empty until measured. Do not wait until Week 10 to begin writing. If a pilot or freeze gate slips, use the Weeks 10–12 margin and update the plan visibly; do not reduce testing, alter thresholds or use final data for tuning to preserve a date.

## Phase gates

| Phase | Active calendar window | Deliverable and lead | Entry conditions | Exit evidence |
| --- | --- | --- | --- | --- |
| P0 Requirements | Week 4, September 21; maintain decisions thereafter | Reviewed immediate scope and interfaces; Simon leads, Ahmed reviews | Contract and user instructions available | Immediate decisions resolved; user reviews requirements needed for the selected first task |
| P1 Interfaces and simulator | Week 4, September 21–23 target | Typed contracts, simulator state machines, trusted context and record schema; Ahmed | P0 review; baseline portions of D03–D05 agreed | Deterministic state/schema tests, no real actuators, hand-executable example task and trace |
| P2 Baseline and gate | Week 4, September 22–25 | Agent integration by Ahmed; development scenarios, independent grader and runner by Simon | Stable P1 interfaces; gate portions of D03/D09–D11/D13 resolved | All three Week 4 criteria demonstrated by September 25; explicit pass/fallback decision |
| P3 Mediator and held-out pilot | Weeks 5–8, September 28–October 23 | Eight rules, repairs and feedback by Ahmed; pilot and independent evaluation by Simon | Baseline gate passes, or recorded fallback; each rule's decisions resolved before implementation | Feature complete by October 16 target, then pilot reviewed; applicable tests pass and D05–D10 settled |
| P4 Final freeze | Week 8, by October 23 and before any final run | Frozen scenario/policy/prompt/grader/analysis manifests; Simon leads, both review | Pilot exit, grader validated, D10–D13 resolved | Hashes, approved run matrix, matching checks, method and cost assumptions |
| P5 Experiments and analysis | Weeks 9–10, October 26–November 6 | Main experiments, trace ablations, end-to-end continuation and failure analysis; Simon | P4 frozen artifact and approved budget | Complete ledger or declared exclusions, reproduced tables/CIs/costs, four security comparisons and relative utility check |
| P6 Artifact and presentation | Weeks 10–12, November 2–20; writing begins earlier | Report, curated artifact, Streamlit dashboard and five-minute demonstration; both, Simon coordinates | Measured results for completed sections; final sign-off requires P5 exit | Complete candidate November 6 target, joint review November 13, final internal sign-off November 20 |

P1 and P2 overlap through agreed interfaces so Simon can build the grader against fixtures while Ahmed builds the simulator. P4 remains a mandatory gate before final experiments. Final artifact acceptance in P6 depends on P5 results, although report and dashboard preparation can overlap. Ahmed is listed as Ahamed in the earlier requirements register; these labels refer to the same planned ownership lane, with full author identity still confirmed before commits.

## Work packages and dependency order

Each row is a candidate work package to select in a later conversation. Each ends with its own verification and human review; a whole row may be split further if its diff becomes difficult to review.

| Work package | Phase | Owner | Requirement IDs | Depends on | Verification focus |
| --- | --- | --- | --- | --- | --- |
| WP-01 Confirm source, roles and immediate threat-model decisions | P0 | Simon | GOV-01–GOV-05, GOV-10 | D02 calendar confirmed; resolve D01 and baseline portions of D03–D05 | Source, scope and decision review |
| WP-02 Agree state/action/context contracts | P1 | Ahamed | SIM-04–SIM-06, OBS-01–OBS-02 | WP-01; baseline state/trust portions of D04–D05 | Reviewed state tables and schema examples; full TTL/replay/repair choices wait for their rule tasks |
| WP-03 Build deterministic simulator and gateway | P1 | Ahamed | SIM-01–SIM-03, SIM-07–SIM-09, OBS-07 | WP-02 | State transitions, reset isolation, no bypasses |
| WP-04 Define development tasks and independent grader | P2 | Simon | DAT-02–DAT-05, EXP-01–EXP-03 | WP-02; D09 and gate grading portions of D10; integrate WP-03 when ready | Hand-labelled full-trace outcomes and allowed attack mutations; repair fixtures added with WP-09 |
| WP-05 Add bounded agent adapter and condition configurations | P2 | Ahamed | AGT-01, AGT-04, AGT-06 | WP-03; D03/D09 | Offline fake-model integration and stop conditions |
| WP-06 Run and review Week 4 gate | P2 | Simon | AGT-02–AGT-03, EXP-08, DEL-01–DEL-02 | WP-04–WP-05; gate portions of D09–D11/D13 | Benign completion, reliably changed action, automatic grade and reproducibility for the baseline; other conditions completed in P3 |
| WP-07 Add schema, authorization and provenance enforcement | P3 | Ahamed | OBS-03–OBS-04, MED-01–MED-04 | WP-06; D05 | Spoofed authority, task scope and payload truth cases |
| WP-08 Add time and replay enforcement | P3 | Ahamed | OBS-05–OBS-06, MED-05–MED-06 | WP-07; D06–D07 | TTL boundaries, duplicates, consumption and resets |
| WP-09 Add state, sequence and task-preserving repair rules | P3 | Ahamed | MED-07–MED-13 | WP-07–WP-08; D04/D08 | Door/temperature/order fixtures, atomicity and repair revalidation |
| WP-10 Integrate pilot and review failures | P3 | Simon | DAT-06, AGT-05, QA-01–QA-03 | WP-09 and independent grader | Full paths, all eight rules, safe/unsafe and useful/useless repairs |
| WP-11 Freeze final scenarios and protocol | P4 | Simon | DAT-01, DAT-07–DAT-09, EXP-04, EXP-09, STA-01–STA-09 | WP-10; D10–D13 | Splits, hashes, denominators, run count, paired synthetic analysis |
| WP-12 Execute main experiments and trace ablations | P5 | Simon | EXP-05–EXP-08, LOG-01–LOG-07 | WP-11; approved budget | Ledger completeness, matching, variant isolation, actual cost |
| WP-13 Analyze and independently reproduce evidence | P5 | Simon | EXP-10, STA-01–STA-09, QA-04 | WP-12 | Bootstrap pairing, failure analysis, reproducible tables |
| WP-14 Prepare report, dashboard and demonstration | P6 | Simon | DEL-03–DEL-04 | WP-13 | Claim checks, artifact navigation and timed demo |

GOV-06–GOV-09 and QA-05 apply throughout. Logging begins with the first integration, not after experiments. Ahamed owns runtime action/state emission (LOG-02); Simon owns record assembly, experiment accounting and analysis. Both approve security-sensitive interfaces, threat model, cost assumptions and the interpretation of results.

## Week 4 gate and fallback

Before measuring the gate, freeze its development task set, repetition count, baseline configuration and the exact criterion for an attack to “reliably” change an action. The contract supplies **at least 70%** benign task completion but does not supply those other details. The gate is not a license to inspect final test tasks.

The gate review is **Friday September 25, 2026**. See the [daily owner assignments and evidence checklist](week_04_tasks.md). Offline fixtures establish software behavior but do not establish language-model benign completion or a reliable injection effect. If provider access or another required dependency prevents measurement, record the gate as unassessable/not met and review fallback; do not mark it passed.

If the gate is missed, retain the contract's fallback: **three devices, 12 tasks, one attack family, deterministic blocking without repair**. D14 selects the retained devices and family. Preserve all security checks applicable to the retained operations and revise the coverage map openly. With the same two forms, three conditions and three repetitions, 12 tasks imply 216 main runs; this is arithmetic for planning, not a separate approved budget. Do not quietly weaken the hypothesis thresholds or re-label the reduced study as the original full benchmark.

## Completion rule for each selected work item

1. Identify requirement IDs, decision dependencies and intended behavior; resolve material uncertainty with Simon.
2. Make the smallest cohesive change and maintain module boundaries and relevant documentation.
3. Run meaningful checks for that change. Keep commands/configuration and their actual outcomes; disclose unrun checks.
4. Present concrete changes and verification for human review. Both collaborators review security-sensitive changes.
5. After the user's relevant commit instruction, inspect explicit paths and create the agreed coherent commit using the confirmed identity.

Suggested message form for later implementation: `feat(mediator): enforce MED-05 sensor freshness` or `test(grading): cover EXP-02 transient violations`. A behavior and its regression tests normally belong in the same cohesive commit. Commit categories should explain the research's progression, not create artificial author contributions or dozens of trivial commits.
