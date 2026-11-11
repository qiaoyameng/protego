# Reproducible data-engineering environment

Upstream: https://github.com/scrapy/protego
Upstream commit: d311dc9154767341aaf7661402cda3ddef9c2225
Validated on Ubuntu 26.04, 3.13.15 (main, Sep  1 2026, 14:18:08) [Clang 22.1.3 ].

Use an isolated virtual environment from this checkout:
```
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-domain.lock
python -m pip install -e .
```
Run the relevant offline baseline:
```
export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 FAST=1
python -m pytest -q -o addopts= tests/test_protego.py tests/test_on_google_spec.py tests/test_unquote.py
```
Measured test process: 0.39 seconds. Only the listed
core tests are claimed. Optional integrations and external services are not
required. Test fixtures are covered by the upstream license. New small test
inputs can be generated locally. Reset by checking out this immutable commit
in a clean directory and recreating the virtual environment.
