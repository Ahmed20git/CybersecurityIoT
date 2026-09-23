"""Build a fresh, isolated environment for one independent run (SIM-03).

Every run gets a new simulator, clock, history, gateway event counter,
evidence registry and request registry. There is no module-level mutable
state, so nothing can carry over between runs.

The experiment harness distributes the pieces: the execution capability goes
to the executor for the condition under test, the environment capability to
the scenario driver, and only ``gateway.observe`` plus the action parser are
exposed to the agent adapter.
"""

from __future__ import annotations

from dataclasses import dataclass

from effectshield.domain.devices import HomeState
from effectshield.gateway.observations import Gateway
from effectshield.gateway.requests import RequestRegistry
from effectshield.simulator.core import EnvironmentCapability, ExecutionCapability, Simulator


@dataclass(frozen=True, slots=True)
class RunEnvironment:
    simulator: Simulator
    gateway: Gateway
    requests: RequestRegistry
    execution_capability: ExecutionCapability
    environment_capability: EnvironmentCapability


def create_run(initial_home: HomeState | None = None, *, start_time_ms: int = 0) -> RunEnvironment:
    simulator = Simulator(initial_home or HomeState(), start_time_ms=start_time_ms)
    execution, environment = simulator.issue_capabilities()
    return RunEnvironment(
        simulator=simulator,
        gateway=Gateway(simulator.snapshot),
        requests=RequestRegistry(),
        execution_capability=execution,
        environment_capability=environment,
    )
