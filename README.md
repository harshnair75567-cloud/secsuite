# secsuite

A unified host security toolkit combining three previously-separate tools
(NIDS, HIPS, FIM) into one package with a shared CLI, config, and logging
layer.

- **NIDS** — network intrusion detection: signature-based deep packet
  inspection on chosen ports, scan-threshold detection, JSON event logging
- **HIPS** — host intrusion prevention: watches file access via atime,
  flags/terminates suspicious process activity against a configurable
  safe-tool allowlist
- **FIM** — file integrity monitoring: hashes a target directory into a
  manifest, then audits against it to flag added/changed/removed files

## Install

```bash
git clone <repo-url>
cd secsuite
pip install .
# or, for development:
pip install -e ".[dev]"
```

## Usage

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

Config lives in `config.json` (created by `secsuite init`) — service
enable/disable flags, NIDS ports/thresholds, HIPS watch zones and safe-tool
allowlist, and general logging settings all live there.

## Architecture

```
secsuite/
  cli.py          argparse-based CLI, dispatches to modules
  daemon.py        multi-service runner (start/stop/status across modules)
  config.py        config load/save/validate
  logging.py        JSON + text logging setup
  modules/
    nids/          signature engine, packet worker
    hips/          file-access monitor, process safety checks
    fim/           hashing engine, manifest, audit
  utils/           fs, hashing, net, process helpers
  tests/           unit tests per module + integration tests
```

Each module runs as an independent service under `daemon.py`'s
`MultiServiceRunner`, so NIDS/HIPS/FIM can be started, stopped, and queried
individually or together.

## Testing

```bash
pip install -e ".[dev]"
pytest
```

## Status

Beta. Core NIDS/HIPS/FIM engines and CLI are implemented with unit +
integration test coverage; SIEM/alerting integrations are not yet built.

## License

MIT
