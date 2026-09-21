# EffectShield

EffectShield is a research project on deterministic runtime enforcement between a tool-using language-model agent and a simulated smart home. It will evaluate whether provenance and state checks reduce unsafe effects and attack success while retaining useful task completion at measured cost.

**Current stage:** requirements review. No simulator, mediator, agent integration or experiments have been implemented. The requirements package is a draft for Simon and Ahamed to review before commits or implementation.

## Project documents

- [Detailed requirements and acceptance criteria](docs/requirements.md)
- [Phases, ownership and verification gates](docs/project_plan.md)
- [Week 4 tasks for Simon and Ahmed](docs/week_04_tasks.md)
- [Research evidence and design implications](docs/research_basis.md)
- [Open decisions, review record and proposed commits](docs/review_and_decisions.md)
- [User prompt history](docs/prompts_history.md)
- [Revised research contract](docs/reference/EffectShield_Revised_Research_Project_Contract.docx)
- [Working instructions](AGENTS.md)

## Responsibilities

| Collaborator | Contract responsibility |
| --- | --- |
| Ahamed, named Ahmed AlAli in the contract | Simulator, device state machines, typed schema, mediator, agent integration and rule tests |
| Simon Kebede Darota (`simonkb`) | Scenario corpus, attacks, baselines, independent grader, experiment runner, analysis and reproducibility |
| Both | Threat model, cost assumptions, security reviews, interpretation, report and demonstration |

The contract identity mapping awaits confirmation before attribution changes. **Current week: September 21–25, 2026 (Week 4)**, with the baseline gate on **Friday September 25**. Aim for a complete candidate in Week 10 (November 2–6), joint review in Week 11 (November 9–13), and **internal completion by November 20 (Week 12)**. The submission window is **November 23–27 (Week 13)**; the exact submission day/time is not yet recorded. The user's clarified schedule supersedes the source contract's later delivery window.

## Working approach

Choose one reviewed requirement or small component at a time. Agree on its behavior, implement it, verify it and review the concrete changes before committing. Keep credentials in environment configuration and preserve requirement IDs in task and commit descriptions. No real smart-home devices or accounts are in scope.
