# Running EffectShield

This guide covers cloning the repository, setting up Python and running the simulator and tests. The examples use `C:\Projects\CybersecurityIoT` on Windows and `~/projects/CybersecurityIoT` on macOS/Linux; replace them with wherever you keep the project.

## Requirements

- Git
- Python 3.11 or newer (tested on 3.11 and 3.14)
- Optional: VS Code with the Python extension

The code needs no API keys or network access.

## 1. Get the code

The implementation is on the `simulator` branch. `main` currently holds only the documents.

```bash
cd C:\Projects                # macOS/Linux: cd ~/projects
git clone https://github.com/Ahmed20git/CybersecurityIoT.git
cd CybersecurityIoT
git switch simulator
```

If you already have the repository, update it instead:

```bash
cd C:\Projects\CybersecurityIoT
git switch simulator
git pull
```

## 2. Create a virtual environment (once)

**Windows (PowerShell)**

```powershell
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

**macOS/Linux**

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

`-e` installs the project in editable mode, so code changes take effect without reinstalling. `[dev]` adds pytest, ruff and mypy. Rerun the install only if `pyproject.toml` changes.

## 3. Activate the environment (every new terminal)

**Windows (PowerShell)**

```powershell
.venv\Scripts\Activate.ps1
```

**macOS/Linux**

```bash
source .venv/bin/activate
```

The prompt should start with `(.venv)`.

## 4. Run it

```bash
python examples/hand_run.py                        # example scenario with a printed state trace
python examples/attack_demo.py                     # two attacks that succeed without the mediator
python -m pytest                                   # all tests
python -m pytest -v tests/unit/test_simulator.py   # one test file, one line per behaviour
python -m pytest -v tests/security                 # trust-boundary tests
```

To check code style and types:

```bash
ruff check .
ruff format --check .
mypy
```

## Trying the simulator interactively

Start `python` and paste:

```python
from effectshield.environment import create_run
from effectshield.domain import DeviceId, parse_action
from effectshield.domain.events import SetPresence

run = create_run()                 # fresh home: door closed and locked, nobody present
sim = run.simulator
print(sim.snapshot().to_dict())

unlock = parse_action('{"schema_version":"1.0","device":"door","operation":"unlock","parameters":{}}')
opn = parse_action('{"schema_version":"1.0","device":"door","operation":"open","parameters":{}}')

# Opening a locked door is rejected with no effect
r = sim.execute([opn], expected_version=sim.state_version, capability=run.execution_capability)
print(r.status, r.reason_code)     # rejected door_locked_cannot_open

# Unlock and open as one all-or-nothing transaction
r = sim.execute([unlock, opn], expected_version=sim.state_version, capability=run.execution_capability)
print(r.status, sim.snapshot().to_dict()["devices"]["door"])

# The scenario harness, not the agent, changes presence; the gateway issues an observation
sim.apply_environment(SetPresence(True), capability=run.environment_capability)
print(run.gateway.observe(DeviceId.PRESENCE_SENSOR).to_agent_dict())

for entry in sim.history:
    print(entry.sequence_no, entry.kind, entry.after.state_version)
```

Exit with `exit()`. [Interfaces](interfaces.md) describes the device states, the action format and the trust boundary.

## VS Code

1. Open the project folder, e.g. **File → Open Folder → `C:\Projects\CybersecurityIoT`**.
2. Press `Ctrl+Shift+P` (`Cmd+Shift+P` on macOS), run **Python: Select Interpreter** and choose `.venv`.
3. Open a new terminal (`` Ctrl+` ``). It should activate `.venv` automatically.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `ModuleNotFoundError: No module named 'effectshield'` | The environment is not active or the project is not installed in it. Activate `.venv` (step 3), or run step 2 again. You can also call the venv's Python directly: `.venv\Scripts\python.exe examples/hand_run.py`. |
| The prompt shows `(base)` instead of `(.venv)` | Anaconda's base environment is active. Run `conda deactivate`, then activate `.venv`. To stop base starting automatically: `conda config --set auto_activate_base false`. |
| PowerShell: "running scripts is disabled on this system" | Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, then activate again. |
| `No such file or directory: examples/hand_run.py`, or no `src` folder | You are on `main`. Run `git switch simulator`. |
| Python older than 3.11 | Install a newer Python and recreate `.venv` with it, e.g. `py -3.14 -m venv .venv`. |
