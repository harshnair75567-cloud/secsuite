# secsuite

![CI](https://github.com/harshnair75567-cloud/secsuite/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.x-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-beta-orange)

A unified host and network security toolkit for Linux. It combines three previously separate tools into one package with a shared CLI, config, and logging layer:

| Module | Purpose |
|---|---|
| **NIDS** | Network intrusion detection: signature-based deep packet inspection on chosen ports, scan-threshold detection, JSON event logging |
| **HIPS** | Host intrusion prevention: watches file access via atime, flags or terminates suspicious process activity against a configurable safe-tool allowlist |
| **FIM** | File integrity monitoring: hashes a directory into a baseline manifest, then audits it to flag added, changed, and removed files |

## Why this exists

Small setups and lab environments rarely have a lightweight, scriptable way to watch the network, the host, and the filesystem together. secsuite runs all three as independent services under one daemon, with one config file and one log format, so events from each layer can be read side by side.

It grew out of three standalone projects I built while learning blue-team techniques (a Scapy-based network IDS, a session-aware host intrusion prevention system, and a SHA-256 file integrity monitor), later consolidated into this package.

## Features

- **Single CLI** for every module (`secsuite nids|hips|fim ...`)
- **Multi-service daemon** to start, stop, and query services individually or together
- **Shared JSON config** with per-service enable flags, ports, thresholds, watch zones, and allowlists
- **Structured JSON logging** for forensic review
- **Test suite** with unit tests per module plus integration tests
- **CI** via GitHub Actions (tests and ruff lint)

## Install

```bash
git clone https://github.com/harshnair75567-cloud/secsuite.git
cd secsuite
pip install .
# or, for development:
pip install -e ".[dev]"
```

> NIDS needs raw socket access, so it typically requires root (`sudo`). Run it in a VM or lab environment.

## Quick start

```bash
secsuite init                                  # create default config.json
secsuite config show                           # show current configuration
secsuite config set nids.ports "[21,22,80]"    # update a config value

secsuite nids start                            # start network IDS
secsuite hips start                            # start host intrusion prevention
secsuite fim baseline                          # snapshot a directory into a manifest
secsuite fim audit                             # check current state against baseline

secsuite start                                 # start all enabled services
secsuite status                                # show service status
secsuite stop                                  # stop all services
```

## Configuration

`secsuite init` writes a `config.json` with:

- Service enable/disable flags
- NIDS ports and detection thresholds
- HIPS watch zones and the safe-tool allowlist
- General logging settings

Change values with `secsuite config set <key> <value>` or edit the file directly.

## How each module works

### NIDS
Inspects packets on the configured ports, matches them against signatures, and applies scan-threshold detection to catch reconnaissance activity. Events are written as structured JSON.

### HIPS
Monitors file access through atime metadata, which avoids depending on file-watch libraries that behave inconsistently in some VM setups. Processes touching watched zones are checked against a configurable allowlist of safe tools; anything else is flagged or terminated.

### FIM
`fim baseline` hashes a target directory (SHA-256) into a manifest. `fim audit` re-hashes and reports files that were added, modified, or removed, which helps surface tampering and injected backdoors.

## Architecture

```
secsuite/
  cli.py          argparse-based CLI, dispatches to modules
  daemon.py       multi-service runner (start/stop/status across modules)
  config.py       config load/save/validate
  logging.py      JSON + text logging setup
  modules/
    nids/         signature engine, packet worker
    hips/         file-access monitor, process safety checks
    fim/          hashing engine, manifest, audit
  utils/          fs, hashing, net, process helpers
  tests/          unit tests per module + integration tests
```

Each module runs as an independent service under `daemon.py`'s `MultiServiceRunner`.

## Testing

```bash
pip install -e ".[dev]"
pytest
```

## Roadmap

See [Roadmap.md](Roadmap.md) for planned features. SIEM and alerting integrations are not built yet.

## Limitations

- Beta software: not a replacement for production EDR/IDS tooling
- Linux only; built and tested in Kali/VirtualBox lab environments
- Signature-based detection will not catch unknown or heavily obfuscated attacks

## Contributing

Issues and pull requests are welcome. Please run `pytest` and `ruff check` before opening a PR.

## License

MIT
