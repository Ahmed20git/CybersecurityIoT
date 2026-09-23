"""Trusted environment events applied by the scenario harness, never the agent."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from effectshield.domain.devices import is_json_number


@dataclass(frozen=True, slots=True)
class SetPresence:
    """Someone arrives at or leaves the monitored area."""

    present: bool

    def __post_init__(self) -> None:
        if not isinstance(self.present, bool):
            raise ValueError("present must be a bool")

    def to_dict(self) -> dict[str, Any]:
        return {"event": "set_presence", "present": self.present}


@dataclass(frozen=True, slots=True)
class SetAmbientTemperature:
    """The simulated room temperature changes. No physical model is implied."""

    ambient_c: float

    def __post_init__(self) -> None:
        if not is_json_number(self.ambient_c) or not math.isfinite(float(self.ambient_c)):
            raise ValueError("ambient_c must be a finite number")
        object.__setattr__(self, "ambient_c", float(self.ambient_c))

    def to_dict(self) -> dict[str, Any]:
        return {"event": "set_ambient_temperature", "ambient_c": self.ambient_c}


EnvironmentEvent = SetPresence | SetAmbientTemperature
