"""CLI for fixtures, rehearsal, human-approved freezing and later live gates."""

import argparse
import json
import sys
import uuid
from copy import deepcopy
from pathlib import Path

from .audit import verify_evidence
from .checks import grader_selfcheck
from .freeze import approval_hashes, freeze_protocol, verify_freeze
from .runner import run_suite
from .storage import load_json, now

ROOT = Path(__file__).resolve().parents[3]


def _output(mode: str) -> Path:
    date = now().split("T")[0]
    return ROOT / "artifacts/local/evaluation" / f"{mode}-{date}-{uuid.uuid4().hex[:8]}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in (
        "offline",
        "simulator-replay",
        "baseline",
        "rehearsal",
        "freeze",
        "approval-hashes",
    ):
        sub = commands.add_parser(command)
        sub.add_argument("--config", type=Path, default=ROOT / "configs/evaluation/gate.json")
        sub.add_argument("--suite", type=Path, default=ROOT / "scenarios/development/baseline.json")
        if command in {"offline", "simulator-replay", "baseline", "rehearsal"}:
            sub.add_argument("--output", type=Path)
            sub.add_argument(
                "--fixtures", type=Path, default=ROOT / "fixtures/evaluation/runs.json"
            )
            if command == "baseline":
                sub.add_argument(
                    "--condition", type=Path, default=ROOT / "configs/conditions/unprotected.json"
                )
            if command == "rehearsal":
                sub.add_argument(
                    "--backend", help="Trusted module:factory; omit for fixture rehearsal"
                )
        elif command == "freeze":
            sub.add_argument("--approval", type=Path, required=True)
            sub.add_argument("--output", type=Path, required=True)
    gate = commands.add_parser("gate")
    gate.add_argument("--freeze", type=Path, required=True)
    gate.add_argument("--output", type=Path)
    verify = commands.add_parser("verify-freeze")
    verify.add_argument("path", type=Path)
    evidence = commands.add_parser("verify-evidence")
    evidence.add_argument("path", type=Path)
    comparison = commands.add_parser("compare-baselines", help="Run matched scripted conditions")
    comparison.add_argument("--config", type=Path, default=ROOT / "configs/evaluation/gate.json")
    comparison.add_argument(
        "--suite", type=Path, default=ROOT / "scenarios/development/authorization.json"
    )
    comparison.add_argument(
        "--fixtures", type=Path, default=ROOT / "fixtures/evaluation/authorization_runs.json"
    )
    comparison.add_argument("--conditions", type=Path, default=ROOT / "configs/conditions")
    comparison.add_argument("--output", type=Path)
    comparison_check = commands.add_parser("verify-comparison")
    comparison_check.add_argument("path", type=Path)
    visualize = commands.add_parser(
        "visualize", help="View saved evidence in an offline HTML report"
    )
    visualize.add_argument("path", type=Path)
    visualize.add_argument("--output", type=Path, help="New .html path outside the evidence bundle")
    commands.add_parser("check-grader")
    args = parser.parse_args(argv)
    try:
        if args.command == "approval-hashes":
            result = approval_hashes(ROOT, args.config, args.suite)
            result["notice"] = "Hashes only: not an approval. Obtain human review before freezing."
        elif args.command == "freeze":
            from effectshield.scenarios import load_suite

            load_suite(args.suite)
            grader_selfcheck(ROOT / "fixtures/evaluation/grader_cases.json")
            result = freeze_protocol(args.config, args.suite, args.output, args.approval)
        elif args.command == "verify-freeze":
            result = verify_freeze(args.path)
        elif args.command == "verify-evidence":
            result = verify_evidence(args.path)
        elif args.command == "compare-baselines":
            from .comparison import run_comparison

            output = args.output or _output("comparison")
            summary = run_comparison(
                args.suite,
                args.fixtures,
                load_json(args.config),
                args.conditions,
                output,
                invocation=[
                    sys.executable,
                    "scripts/evaluate.py",
                    *(sys.argv[1:] if argv is None else argv),
                ],
            )
            result = {
                "output": str(output.resolve()),
                "status": summary["status"],
                "conditions": summary["conditions"],
                "notice": summary["notice"],
            }
        elif args.command == "verify-comparison":
            from .comparison import verify_comparison

            result = verify_comparison(args.path)
        elif args.command == "visualize":
            from .visualize import write_visualization

            result = write_visualization(args.path, args.output)
        elif args.command == "check-grader":
            result = grader_selfcheck(ROOT / "fixtures/evaluation/grader_cases.json")
        else:
            if args.command == "gate":
                verify_freeze(args.freeze)
                config = load_json(args.freeze / "protocol.json")
                suite = args.freeze / "suite.json"
                fixture = None
                backend = config["backend_approval"]["module"]
                freeze_path = args.freeze
            else:
                config = deepcopy(load_json(args.config))
                suite = args.suite
                backend = getattr(args, "backend", None)
                fixture = None if backend else args.fixtures
                freeze_path = None
                if fixture:
                    config["model"] = {
                        "provider": (
                            "scripted-model"
                            if args.command == "baseline"
                            else "simulator-replay"
                            if args.command == "simulator-replay"
                            else "static-fixtures"
                        ),
                        "version": (
                            "scripted-model-v1"
                            if args.command == "baseline"
                            else "recorded-proposals-v1"
                            if args.command == "simulator-replay"
                            else "static-fixture-v1"
                        ),
                        "date": "2026-09-28",
                        "settings": {},
                        "seed": 0,
                        "seed_status": "supported",
                    }
            condition = None
            if args.command == "baseline":
                from effectshield.agent.conditions import load_condition

                condition = load_condition(args.condition).to_dict()
                config["prompt_version"] = condition["prompt_version"]
            output = args.output or _output(args.command)
            summary = run_suite(
                suite,
                config,
                output,
                mode=args.command,
                condition=condition,
                backend_spec=backend,
                fixture_path=fixture,
                freeze_path=freeze_path,
                invocation=[
                    sys.executable,
                    "scripts/evaluate.py",
                    *(sys.argv[1:] if argv is None else argv),
                ],
            )
            result = {
                **({"condition": condition["condition_id"]} if condition else {}),
                "output": str(output.resolve()),
                "mode": summary["mode"],
                "attempts": summary["attempts"],
                "criteria": summary["criteria"],
            }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, ImportError) as error:
        from .storage import redact

        print(redact(f"Blocked: {error}"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
