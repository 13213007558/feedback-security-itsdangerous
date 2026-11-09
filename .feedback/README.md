# Feedback task starting environment

Upstream: https://github.com/pallets/itsdangerous
Upstream commit: `672971d66a2ef9f85151e53283113f33d642dabd`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.
The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests
```

Observed baseline (2026-11-09): `297 passed in 0.55s`
Whole-command wall time: 0.943 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
