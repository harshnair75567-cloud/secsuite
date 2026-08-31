# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- GitHub Actions CI workflow: runs test suite (Python 3.9–3.12) and ruff lint on every push/PR to `main`.

## [1.0.0]

### Added
- Initial unified release combining NIDS, HIPS, and FIM into a single package.
- Shared CLI (`secsuite.cli`), config layer, and JSON/text logging.
- `MultiServiceRunner` in `daemon.py` for starting/stopping/querying all services together.
- Unit tests for config, fs, hashing, logging, FIM, and NIDS engine; integration test suite.
