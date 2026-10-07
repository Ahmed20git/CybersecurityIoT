"""Execute recorded proposals against Ahmed's simulator and gateway offline.

This is an experiment replay harness, not an agent, inference adapter, policy
mediator, or second simulator. Proposal sequences are authored fixture input;
the native parser and simulator determine their actual effects. The attacked
sequence therefore demonstrates integration, not observed injection success.
"""

from __future__ import annotations

from collections.abc import Generator, Iterator
from copy import deepcopy
from pathlib import Path
from typing import Any

from effectshield.domain.actions import ActionProposal, parse_action
from effectshield.domain.context import Observation, Permission
from effectshield.domain.devices import (
    DeviceId,
    DoorPosition,
    DoorState,
    FanState,
    HomeState,
    LightState,
    LockState,
    Operation,
    Power,
    PresenceState,
    ThermostatState,
)
from effectshield.domain.errors import ActionSchemaError
from effectshield.environment import RunEnvironment, create_run
from effectshield.gateway.observations import with_payload_changes
from effectshield.scenarios import validate_state

from .backends import load_fixture_trace, synthetic_usage
from .storage import canonical


def home_from_snapshot(snapshot: dict[str, Any]) -> HomeState:
    """Construct native immutable initial state; do not translate or discard fields."""
    validate_state(snapshot)
    devices = snapshot["devices"]
    home = HomeState(
        light=LightState(Power(devices["light"]["power"])),
        fan=FanState(Power(devices["fan"]["power"])),
        thermostat=ThermostatState(
            Power(devices["thermostat"]["power"]),
            devices["thermostat"]["setpoint_c"],
            devices["thermostat"]["ambient_c"],
        ),
        door=DoorState(
            DoorPosition(devices["door"]["position"]), LockState(devices["door"]["lock"])
        ),
        presence_sensor=PresenceState(devices["presence_sensor"]["present"]),
    )
    if canonical(home.to_dict()) != canonical(devices):
        raise ValueError("Initial device snapshot must retain exact native JSON values and types")
    return home


class NativeEvaluationBackend:
    """Shared trusted runtime wiring; no model choice, proposals, or policy enforcement."""

    def __init__(self) -> None:
        self.environment: RunEnvironment | None = None
        self._emitted_history = 0
        self._started = False

    def reset(self, initial_state: dict[str, Any], seed: int | None) -> dict[str, Any]:
        if initial_state.get("state_version") != 0:
            raise ValueError("Replay must start from a fresh native state version zero")
        self.environment = create_run(
            home_from_snapshot(initial_state), start_time_ms=initial_state["time_ms"]
        )
        self._emitted_history = 0
        self._started = False
        return self.environment.simulator.snapshot().to_dict()

    def _history_events(self) -> Iterator[dict[str, Any]]:
        # Drain authoritative history, including clock/environment entries. Do
        # not rebuild snapshots from actions or copy the fixture's expected trace.
        assert self.environment is not None
        for entry in self.environment.simulator.history[self._emitted_history :]:
            self._emitted_history += 1
            yield {"type": "committed_transition", **entry.to_dict()}

    def _finish(self, status: str, error: str | None = None) -> dict[str, Any]:
        assert self.environment is not None
        event: dict[str, Any] = {
            "type": "finish",
            "status": status,
            "final_state": self.environment.simulator.snapshot().to_dict(),
            "committed_count": len(self.environment.simulator.history),
        }
        if error is not None:
            event["error"] = error
        return event

    def _prepare(
        self, request: dict[str, Any], observations: list[dict[str, Any]]
    ) -> Iterator[dict[str, Any]]:
        if self.environment is None or self._started:
            raise ValueError("Reset a fresh environment before each recorded proposal replay")
        self._started = True
        run = self.environment
        permissions = []
        for value in request["permissions"]:
            device, operation = value.split(".", 1)
            permissions.append(Permission(DeviceId(device), Operation(operation)))
        issued = run.requests.issue(
            principal_id=request["principal_id"],
            request_text=request["request_text"],
            permissions=permissions,
            issued_at_ms=run.simulator.now_ms,
        )
        if canonical(issued.to_dict()) != canonical(request):
            raise ValueError("Trusted request differs from the native request registry record")
        self._bind_request(issued.request_id)
        yield {"type": "message", "role": "user", "content": issued.to_dict()}
        for expected in observations:
            observed = run.gateway.observe(DeviceId(expected["envelope"]["device"]))
            # The one permitted attack changes only message text. Fact fields and
            # the full gateway envelope must still match the issued native record.
            delivered = with_payload_changes(observed, {"message": expected["payload"]["message"]})
            if canonical(delivered.to_agent_dict()) != canonical(expected):
                raise ValueError("Initial observation changed protected gateway metadata or facts")
            delivered = self._deliver(delivered)
            yield {"type": "message", "role": "tool", "content": delivered.to_agent_dict()}

    def _bind_request(self, request_id: str) -> None:
        """Hook: a protected backend binds the run's issued request. Unprotected runs do nothing."""

    def _deliver(self, observation: Observation) -> Observation:
        """Hook: a protected backend ingests every observation placed in the agent's context."""
        return observation

    def _execute(self, proposal: ActionProposal) -> Generator[dict[str, Any], None, dict[str, Any]]:
        assert self.environment is not None
        run = self.environment
        if proposal.operation is Operation.READ:
            observed = run.gateway.observe(proposal.device)
            yield from self._history_events()
            yield {
                "type": "observation",
                "receipt": {
                    "action": proposal.to_dict(),
                    "observation": observed.to_agent_dict(),
                    "snapshot": run.simulator.snapshot().to_dict(),
                },
            }
            return {"status": "observed", "observation": observed.to_agent_dict()}
        result = run.simulator.execute(
            [proposal],
            expected_version=run.simulator.state_version,
            capability=run.execution_capability,
        )
        yield from self._history_events()
        return result.to_dict()


class SimulatorReplayBackend(NativeEvaluationBackend):
    """A fresh native run for each reset, driven exclusively by recorded proposals."""

    kind = "fixture"

    def __init__(self, fixture_path: str | Path, scenario_id: str) -> None:
        super().__init__()
        self.trace = load_fixture_trace(fixture_path, scenario_id)

    def reset(self, initial_state: dict[str, Any], seed: int | None) -> dict[str, Any]:
        if canonical(initial_state) != canonical(self.trace["initial_state"]):
            raise ValueError("Recorded proposal replay initial state differs from requested reset")
        return super().reset(initial_state, seed)

    def run(
        self, request: dict[str, Any], observations: list[dict[str, Any]], config: dict[str, Any]
    ) -> Iterator[dict[str, Any]]:
        yield from self._prepare(request, observations)
        yield synthetic_usage(config, replay=True)
        for recorded in self.trace["proposed_actions"]:
            yield from self._history_events()
            yield {"type": "proposed_action", "action": deepcopy(recorded)}
            try:
                proposal = parse_action(canonical(recorded))
            except ActionSchemaError as error:
                yield from self._history_events()
                yield self._finish(
                    "invalid_response", f"Native action parser rejected proposal: {error}"
                )
                return
            result = yield from self._execute(proposal)
            if result["status"] == "rejected":
                yield self._finish(
                    "invalid_response",
                    f"Native simulator rejected proposal: {result['reason_code']}",
                )
                return
        yield from self._history_events()
        yield self._finish("completed")
