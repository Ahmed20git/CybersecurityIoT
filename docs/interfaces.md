# EffectShield interfaces: WP-02 and WP-03

Status: **implemented for review, 2026-09-23**. This covers WP-02 (state, action and context contracts) and WP-03 (deterministic simulator and trusted gateway) from the [project plan](project_plan.md). Mediator rules 1–8 are planned in WP-07 to WP-09. Choices marked **Proposed** fill gaps left open by D04, D05 and D07 in the [open decisions](requirements.md#open-decisions). Both collaborators should review them before the mediator relies on them.

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

- input over 4096 bytes, invalid UTF-8, malformed JSON or nesting deeper than 4 containers (bounded explicitly across Python versions)
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

## Agent adapter and conditions (WP-05)

Status: **implemented for review, 2026-10-05**. Covers AGT-01, AGT-04 and AGT-06. The condition files supply versioned inputs for AGT-02 and AGT-03 and remain drafts until Simon's protocol review.

| Path | Requirement IDs | Responsibility |
| --- | --- | --- |
| `src/effectshield/agent/baseline.py` | AGT-01, AGT-04 | Bounded proposal loop: one typed JSON action per call, strict parsing, call/step/token/cost/wall-clock bounds |
| `src/effectshield/agent/continuation.py` | AGT-04 | Frozen continuation protocol `continuation-draft/v1` and exact agent-visible feedback fields |
| `src/effectshield/agent/conditions.py` | AGT-02, AGT-03 | Strict condition loader and treatment-difference check |
| `src/effectshield/agent/openai_client.py` | AGT-06 | The only provider-specific code |
| `src/effectshield/experiments/baseline.py` | AGT-06 | `ScriptedModel` offline fixture adapter; `BaselineBackend` accepts a condition |
| `configs/conditions/*.json` | AGT-02 | `unprotected`, `safety_prompt_only` and `effectshield` |

### Conditions (Proposed; AGT-02 review pending)

| Condition | Prompt version | Safety instruction | Enforcement |
| --- | --- | --- | --- |
| `unprotected` | `baseline-prompt-draft/v1` | none | none |
| `safety_prompt_only` | `safety-prompt-draft/v1` | yes, in the system message | none, so no hidden shield |
| `effectshield` | `baseline-prompt-draft/v1` | none | `effectshield` mediator |

The loader rejects any other shape: each condition ID fixes whether a safety instruction exists and which enforcement applies. EffectShield must reuse the unprotected prompt so its only treatment is enforcement. `treatment_differences` raises if two conditions differ outside `condition_id`, `condition_version`, `prompt_version`, `safety_instruction` and `enforcement`. The agent refuses a condition whose prompt version differs from the run configuration. `BaselineBackend` refuses `effectshield` until the mediator exists (WP-07 onward), rather than running it unprotected under that name.

### Continuation protocol (Proposed; D09 review pending)

The harness reports exactly one outcome per proposal. Feedback must contain exactly the listed fields; anything else is a harness defect and raises.

| Outcome | Source | Agent-visible fields | Agent continues? |
| --- | --- | --- | --- |
| `committed` | allow, then simulator | `status`, `transaction_id`, `version_before`, `version_after`, `reason_code`, `failed_index` | yes |
| `observed` | allow, then gateway read | `status`, `observation` | yes |
| `rejected` | allow, then simulator refuses | same as `committed`; `reason_code` required | yes, counts as a refusal |
| `blocked` | mediator | `status`, `reason_code`, `state_version` | yes, counts as a refusal |
| `repaired` | mediator | `status`, `transaction_id`, `version_before`, `version_after`, `reason_code`, `executed_actions` | yes |
| `abstained` | mediator | `status`, `reason_code` | no: stops `abstained` without another call |
| `escalated` | mediator | `status`, `reason_code` | no: stops `escalated` without another call |

- A block or rejection gives no extra budget: every proposal consumes the same calls, steps, tokens and cost as in any other condition.
- Two consecutive refusals (`MAX_CONSECUTIVE_REFUSALS`) stop the run as `budget_exceeded`, so retry loops terminate; any non-refusal outcome resets the count.
- The agent also stops with `timeout` before a call once `limits.wall_timeout_s` has elapsed. The runner's process-level timeout still applies.
- The runner and grader do not yet accept the `escalated` termination. Adding it is an integration item for when the mediator produces it.

## Verification

```bash
pip install -e ".[dev]"
python -m pytest        # unit, security and integration tests; offline, no credentials
ruff check . && ruff format --check .
mypy                    # strict, src/ only
PYTHONPATH=src python examples/hand_run.py
```

## Related work

- Mediator rules 1–8, repair and escalation remain planned in WP-07 to WP-09. The continuation protocol above fixes how the agent reacts to their decisions.
- The implemented agent adapter, baseline executor, scenarios, attack builder, independent grader and run ledger are documented in the [evaluation guide](evaluation_guide.md).
- Full LOG-02 records will include mediator decisions and repairs when those components are implemented.
