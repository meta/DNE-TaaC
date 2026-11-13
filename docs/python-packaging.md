# Python packaging

TAAC's Python installation path provides the engine and authoring libraries
through standard Python packages. It coexists with the Docker build.

## Installation

Use a Python 3.12 virtual environment on Linux x86_64 with glibc 2.34 or newer. The current artifacts
contain native extensions built for that interpreter and platform.

From a wheelhouse containing `dne-taac` and `dne-taac-runtime`:

```bash
python -m pip install --find-links /path/to/wheelhouse dne-taac
```

With uv and an activated environment:

```bash
uv pip install --find-links /path/to/wheelhouse dne-taac
```

You can also install the OSS source checkout while using the prebuilt native
runtime wheel:

```bash
python -m pip install --find-links /path/to/wheelhouse .
```

The Python build backend packages TAAC's sources. Installing the runtime wheel
supplies the generated Thrift bindings and native libraries. Users installing
these artifacts do not need Docker, getdeps, CMake, or a C++ compiler.

The runtime wheel has not been published to a public index yet, so the
wheelhouse is currently required. Other operating systems, architectures, and
Python versions need their own native artifacts and verification.

## Running the engine

```bash
tictaac run \
  --test-config-json compiled_configs/example.json \
  --device-info-csv devices.csv \
  --circuit-info-csv circuits.csv \
  --json
```

For the existing Python-config runner:

```bash
python -m taac.runner.oss_entry_point \
  --test-configs configs/example.py \
  --dut switch1 \
  --device-info-csv devices.csv \
  --circuit-info-csv circuits.csv
```

The CLI entry points establish OSS mode before importing the runtime. Scripts
that import authoring utilities directly should set `TAAC_OSS=1` before their
first TAAC import, as in the existing OSS workflow.

## Config export

`taac-compile` exposes the existing registered-config exporter. It writes
Thrift JSON, with one config per line. It is not a new general `conf build`
implementation for arbitrary Python source directories.

The current registered OSS OTG factory cannot be exported successfully: it
passes `port_location` to `DirectIxiaConnection`, but the schema does not define
that field. This packaging change preserves the Python implementation and the
schema, so that existing issue remains. The engine and JSON serialization
utilities work with configs that use supported schema fields.

## Package builds at Meta

The internal packaging target builds the native runtime with shared Buck
`python_wheel` tooling and creates the application wheel with the standard
Python build frontend in a Meta-managed environment:

```bash
buck2 build fbcode//neteng/test_infra/dne/taac/internal/oss_packaging:wheels_py312 \
  --show-full-json-output
```

The output is a wheelhouse containing both distributions. `pyproject.toml`
owns application package metadata, dependency requirements, and CLI entry
points. Package discovery includes new public Python modules and resource files
without adding file patterns to the packaging rules. The application wheel owns
the OSS runner initializer; the runtime wheel does not duplicate that file.
The internal packaging definition derives the interpreter platform, environment
constraints, and native linkage repair from one Python version setting.

The native runtime target collects the existing Thrift generation and
runtime targets, creates the compatibility aliases used by OSS TAAC, and links
their native dependencies into the wheel. The release step removes direct
linkage to `libpython` and uses `auditwheel` to bundle additional shared
libraries, strip debug information, and validate the manylinux platform tag.

The source preview reads the working copy and applies the existing TAAC OSS
staging rules. It does not require a commit or a submission. Exact ShipIt
verification and release publication remain separate steps.
