# EffectShield evidence artifact and reproduction

Updated 2026-11-06. This guide covers LOG-05, LOG-07 and DEL-03. It explains where the retained research evidence lives and how its checksums are verified. It also lists the commands that regenerate every reported table, figure and dashboard number without credentials or model calls. The [full report](report/effectshield_report.pdf) and its [LaTeX source](report/effectshield_report.tex) present the results; the [project plan](project_plan.md#final-study-november-4) records the run itself.

## What the artifact contains

All retained evidence is under `artifacts/local/evaluation/` and is shared through Git under D13 (see the [decision register](requirements.md#open-decisions)). [`ARTIFACT_MANIFEST.json`](../artifacts/local/evaluation/ARTIFACT_MANIFEST.json) lists every item with its identity and SHA-256 checksum:

| Manifest section | Contents |
| --- | --- |
| `bundles` | Every evidence bundle (baseline gate, rehearsal, pilot and the three final-study condition batches) with its batch ID, mode, condition, file count and the checksum of its `evidence_manifest.json`, which in turn checksums every file of the bundle |
| `comparisons` | Every condition comparison, with the checksums of its pre-run `comparison_plan.json` and its `comparison.json` |
| `freezes` | Every approval-bound freeze, with its freeze ID and implementation hash |
| `reports` | Every other retained file: analyses, ablations, latency, billing, review records and Ahmed's independent replay |
| `code_revision`, `dependency_files` | The Git revision the manifest was built from and the checksums of `pyproject.toml`, `requirements-dev.txt` and `requirements-dashboard.txt` |

The final study is `final-2026-11-04/`. It has one bundle per condition, the comparison plan with the block-randomized order, `comparison.json`, `analysis.json` (v1, produced on November 4) and `analysis-v2.json`. The v2 analysis has the same v1 fields plus the STA-06 decision confusion table. Its freeze is `final-freeze/`, and `final-2026-11-04-review/` holds Ahmed's independent re-grade and replay.

## Verify the package

Runtime and analysis code use only the Python standard library, so verification needs no third-party packages. From the repository root:

```sh
python3 -m venv /tmp/effectshield-check
PYTHONPATH=src /tmp/effectshield-check/bin/python scripts/evaluate.py verify-artifact artifacts/local/evaluation/ARTIFACT_MANIFEST.json
```

`verify-artifact` recomputes every listed checksum. It re-runs the bundle audit (`verify-evidence`), the comparison audit (`verify-comparison`), which re-grades every trace and checks matching and the plan, and the freeze audit (`verify-freeze`). It fails on the first difference. Remove the temporary environment afterwards.

## Regenerate the reported numbers

These commands write to a temporary directory. Compare each output with the retained file using `cmp`:

```sh
E=artifacts/local/evaluation
OUT=$(mktemp -d)
export PYTHONPATH=src
python3 scripts/evaluate.py analyze $E/final-2026-11-04 --output $OUT/analysis.json
cmp $OUT/analysis.json $E/final-2026-11-04/analysis-v2.json
for c in effectshield unprotected safety_prompt_only; do
  python3 scripts/evaluate.py ablate $E/final-2026-11-04/$c --output $OUT/ablation-$c.json
  cmp $OUT/ablation-$c.json $E/final-2026-11-04-ablation-$c.json
done
python3 scripts/evaluate.py billing --output $OUT/billing.json
cmp $OUT/billing.json $E/billing-2026-11-06.json
python3 scripts/evaluate.py latency $E/final-2026-11-04 --output $OUT/latency.json
```

| Output | Requirement | Deterministic? |
| --- | --- | --- |
| `analysis-v2.json`: rates, denominators, task-cluster bootstrap intervals (10,000 replicates, seed 20261102), exact bounds, sensitivity, utility check, weighted loss, families, decision confusion | STA-01–STA-09 | Byte-identical on regeneration |
| `final-2026-11-04-ablation-*.json`: trace-replay ablations | EXP-05, EXP-06 | Byte-identical |
| `billing-2026-11-06.json`: attempts, calls, tokens and estimated cost per bundle and day | LOG-04 | Byte-identical |
| `final-2026-11-04-latency.json`: mediator-only decision time over an offline replay and recorded end-to-end task latency | LOG-03 | Timing values vary with the machine; recorded task latencies and the replayed verdicts (0 mismatches with `decisions.json`) do not |

The report's numbers come from `docs/report/generated/results.tex`. `python3 scripts/report_tables.py` regenerates that file from the retained outputs, and `--check` fails if it is stale; the test suite runs the check. The report builds with `tectonic docs/report/effectshield_report.tex`.

## Dashboard and demonstration

The Streamlit dashboard is read-only. Every page loads the saved results, verifies the comparison and freeze, and shows rates with denominators and 95% intervals. Device messages, model output and proposals appear only as plain text, code or tables, never as rendered markup (LOG-06).

```sh
python3 -m pip install -r requirements-dashboard.txt
PYTHONPATH=src streamlit run src/effectshield/dashboard/app.py
```

The narrated demonstration video (`effectshield_demo.mp4`, 4:35) records this dashboard. The video is shared outside Git; its [subtitles](demo/effectshield_demo.srt) are tracked. Its [script](demo/demo_script.md) is generated by `scripts/record_demo.py` from [`segments.json`](demo/segments.json), with every number filled from the retained evidence. To record it again, start the dashboard on port 8765 and run `python3 scripts/record_demo.py --record OUT_DIR`; `docs/demo/*.mp4` is ignored by Git. Recording also needs Playwright with Chromium, ffmpeg and the macOS `say` voice; these are recording tools, not project dependencies.

## Limits of reproduction

- **Model outputs cannot be regenerated.** The provider does not support seeded sampling, and the frozen freeze can be claimed only once. A new live study needs credentials, an approved budget and a new reviewed freeze. Everything downstream of the recorded model messages is reproducible offline.
- **Actual billing is not reconciled yet.** `billing-2026-11-06.json` reports estimated cost from the published tariff (USD 0.2255 for all live attempts, USD 0.1829 for the final study). Its status remains "actual billing unavailable" until the provider's billed amounts per UTC day are supplied with `billing --actual FILE`.
- **Team package, not a public release.** Some retained files embed the original local machine path. Releasing the evidence beyond Simon and Ahmed needs a reviewed D13 decision.
- **Superseded formats.** Earlier bundles keep their original bytes. Audit them with the code revision recorded in their manifest when the current tools no longer read their format.
