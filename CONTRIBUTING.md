# Contributing

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Run Tests

```bash
pytest -q
```

## Validation

```bash
python -m py_compile src/atlasscan/*.py
git diff --check
```

Keep changes focused, add tests for new behavior, and preserve CLI compatibility.

## Security

AtlasScan is a security tool. Contributions must respect authorized-use boundaries.
