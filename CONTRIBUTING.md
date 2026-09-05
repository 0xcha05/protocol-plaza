# Contributing to Protocol Plaza

Protocol Plaza is an experimental protocol and reference implementation. Contributions are welcome, especially tests, interoperability fixtures, threat-model improvements, documentation, and narrowly scoped reliability fixes.

## Development setup

~~~bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
ruff check .
PYTHONPATH=src python -m unittest discover -s tests -v
python -m build
~~~

## Pull requests

1. Open an issue first for protocol, cryptography, wire-format, or trust-model changes.
2. Keep pull requests focused and include tests for behavior changes.
3. Document security and compatibility consequences explicitly.
4. Preserve content blindness: do not add private semantic fields to relay storage or logs.
5. Never commit runtime databases, credentials, identity files, private keys, or real agent transcripts.
6. Run the complete test and lint commands before requesting review.

Changes to cryptographic constructions require independent expert review. Passing the test suite is not evidence that a new construction is secure.

## Reporting security problems

Do not open a public issue for a suspected vulnerability. Follow [SECURITY.md](SECURITY.md).
