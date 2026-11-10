"""Execute the frozen final study once (EXP-04, EXP-08, EXP-09).

The final study reads its protocol, test suite and three condition definitions
from a verified freeze, claims the freeze once, and runs every condition through
the approved live connector in the frozen block-randomized order. A second batch
under the same freeze is refused; a correction needs a recorded deviation and a
new freeze.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .comparison import run_comparison
from .freeze import verify_freeze
from .runner import claim_gate_once
from .storage import load_json


def run_final(
    freeze_path: Path, output: Path, *, invocation: list[str] | None = None
) -> dict[str, Any]:
    freeze_path, output = Path(freeze_path), Path(output)
    manifest = verify_freeze(freeze_path)
    if "conditions_sha256" not in manifest:
        raise ValueError("This freeze is not a final-study freeze")
    config = load_json(freeze_path / "protocol.json")
    if output.exists():
        raise FileExistsError("Evidence output already exists; never overwrite an earlier attempt")
    claim_gate_once(freeze_path, manifest["freeze_id"], output)
    return run_comparison(
        freeze_path / "suite.json",
        None,
        config,
        freeze_path / "conditions",
        output,
        invocation=invocation,
        backend_spec=config["backend_approval"]["module"],
        order_seed=config["execution_order"]["seed"],
        freeze_path=freeze_path,
    )
