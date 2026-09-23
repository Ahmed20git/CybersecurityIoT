# EffectShield interfaces: WP-02 and WP-03

Status: **implemented for review, 2026-09-23**. This covers WP-02 (state, action and context contracts) and WP-03 (deterministic simulator and trusted gateway) from the [project plan](project_plan.md). Nothing here is a mediator policy: rules 1–8 are enforced in WP-07 to WP-09. Choices marked **Proposed** fill gaps left open by D04, D05 and D07. Both collaborators should review them before the mediator relies on them.

## Module map

| Path | Requirement IDs | Responsibility |
| --- | --- | --- |
| `src/effectshield/domain/devices.py` | SIM-01, SIM-04 | Device IDs, operations and frozen device states |
| `src/effectshield/domain/catalog.py` | SIM-04, SIM-05 | The supported device/operation/parameter table |
| `src/effectshield/domain/actions.py` | SIM-05, SIM-06 | Strict typed JSON action parser |
| `src/effectshield/domain/context.py` | OBS-01, OBS-02, SIM-06 | Request context, permissions, envelopes and observations |
| `src/effectshield/domain/events.py` | SIM-03 | Trusted environment events (presence, ambient temperature) |
| `src/effectshield/simulator/transitions.py` | SIM-01, SIM-08 | Pure transition functions (simulator validity only) |
| `src/effectshield/simulator/core.py` | SIM-02, SIM-07, SIM-09 | State owner, clock, capabilities, atomic transactions, trace |
| `src/effectshield/gateway/observations.py` | OBS-01, OBS-02, OBS-07 | Observation issuance, evidence registry, payload mutation manifest, replay path |
| `src/effectshield/gateway/requests.py` | OBS-01, SIM-06 | Harness-issued request identity and permissions |
| `src/effectshield/environment.py` | SIM-03 | Fresh, isolated environment per run |

## Device state tables (Proposed D04 baseline)

| Device | State | Agent operations | Invalid transitions |
| --- | --- | --- | --- |
| light | `power`: on/off | `read`, `turn_on`, `turn_off` | none |
| fan | `power`: on/off (no speed, per the contract) | `read`, `turn_on`, `turn_off` | none |
| thermostat | `power`, `setpoint_c`, `ambient_c` (Celsius) | `read`, `turn_on`, `turn_off`, `set_setpoint(setpoint_c)` | setpoint outside the **device** range 0–50 C |
| door | `position`: open/closed; `lock`: locked/unlocked | `read`, `lock`, `unlock`, `open`, `close` | `open` while locked; `lock` while open |
| presence_sensor | `present`: bool | `read` only | agent cannot change it |

- **No-ops:** repeating a satisfied operation (e.g. `turn_on` when on) is valid and does not bump the state version.
- **Environment events:** presence and ambient temperature change only through `SetPresence` and `SetAmbientTemperature`, applied by the scenario harness.
- **Device range vs. policy range:** the 0–50 C device range is deliberately wider than the contract's 16–30 C policy range. A 35 C request is a valid simulator operation that must reach the mediator (SIM-05, SIM-08). The simulator never clamps.
- **Open for D04:** entry versus egress door operations are not distinguished yet.

## Action schema (SIM-05)

```json
{
  "schema_version": "1.0",
  "device": "thermostat",
  "operation": "set_setpoint",
  "parameters": {"setpoint_c": 22},
  "evidence_refs": ["obs-000003"]
}
```

`parse_action` rejects, with stable `SchemaErrorCode`s:

- input over 4096 bytes, invalid UTF-8, malformed JSON or excessive nesting
- duplicate keys, `NaN`/`Infinity` and overflowing numbers
- unknown or missing fields, including any agent-asserted `identity`, `source`, timestamp, event ID or request ID (SIM-06)
- unknown devices or operations, and operations the device does not support
- unknown or missing parameters, wrong types, booleans used as numbers, and `null`
- more than 8 evidence references, malformed references, or duplicated references

`evidence_refs` are only pointers. Trusted code resolves them through the gateway's evidence registry; the agent's account of what they mean is never trusted.

## Trust boundary

| Object | Issued by | Agent can… |
| --- | --- | --- |
| `RequestContext` (request ID, principal, permissions) | `RequestRegistry` (scenario harness) | nothing; it never receives a writable handle |
| `Envelope` (source ID, event ID, gateway time) | `Gateway.observe` | read a copy |
| Observation payload | `Gateway.observe`, then untrusted | read; attacker may edit fields listed in `WRITABLE_PAYLOAD_FIELDS` |
| `EvidenceRecord` (canonical facts, original envelope, state version) | `Gateway` | nothing; trusted components get the read-only `EvidenceView` |
| Device state and clock | `Simulator` | read immutable snapshots only |

- **Mutation capabilities:** `Simulator.issue_capabilities()` returns an `ExecutionCapability` and an `EnvironmentCapability` once per run.
  - Protected condition: only the mediator's executor holds the execution capability (SIM-07).
  - Baseline conditions: the harness's direct executor holds it.
  - The agent adapter holds neither.
  - Python cannot enforce this against code in the same process, so the boundary holds by construction and `tests/security/test_trust_boundary.py` checks it.
- **Attacks:** `with_payload_changes` is the only edit path for the attack harness (OBS-02, DAT-05). It preserves the original envelope, and `Gateway.redeliver` replays only envelopes this gateway issued. A replay never gets a new timestamp or event ID.
- **Payload truth:** payload values and the free-text `message` are both writable, because an authentic envelope does not make the payload true (OBS-04). The registry's canonical facts show what was actually observed.

## Gateway identifiers (Proposed D07 baseline)

- One gateway-wide event counter starts at 1 in each run and strictly increases across all sources.
- The observation ID is `obs-` followed by the zero-padded event ID; the source ID is `gateway/<device>`.
- Gateway time is the simulator clock at issuance, in integer milliseconds.
- Consumption and duplicate policy (rule 5) is **not** decided here; it waits for D07 in WP-08.

## Transactions (SIM-09)

`Simulator.execute(actions, expected_version=..., capability=...)` works as follows:

- It is all-or-nothing. It is rejected with no effect if the batch is empty, longer than 8 actions, or checked against a stale `state_version`, or if any step is physically invalid. A rejection reports `failed_index`.
- Each committed step produces a `TraceEntry` with before and after snapshots. Clock advances and environment events are traced too (a partial LOG-02 emission).
- `Simulator.preview` predicts intermediate states without mutating, for repair revalidation later (MED-11).

The 8-action bound is only a structural limit; D08 sets the repair bound.

## Verification

```bash
pip install -e ".[dev]"
python -m pytest        # unit, security and integration tests; offline, no credentials
ruff check . && ruff format --check .
mypy                    # strict, src/ only
PYTHONPATH=src python examples/hand_run.py
```

## Not in this change

- Mediator rules 1–8, repair and escalation (WP-07 to WP-09).
- The agent adapter and the direct baseline executor (WP-05).
- The grader, scenarios, attack builder and run ledger (Simon's WP-04 and WP-06).
- Full LOG-02 run records.
