# integrity-guard

File integrity monitoring for critical directories. Records a cryptographic
baseline of a directory tree, then detects any file that is later **added,
modified, deleted**, or has its **permissions or ownership** changed.

This is the host-based detection layer that catches the things that matter:
a web shell dropped into a webroot, a tampered system binary, an
unauthorised edit to a configuration file.

## Why it exists

Most intrusions leave a trace on disk. A web shell is just a new `.php` file
in a directory that should not have changed since deployment. `integrity-guard`
turns "should not have changed" into something you can actually verify and
alert on.

## Requirements

Python 3.10 or newer. No packages to install.

## Usage

```bash
# 1. Record a baseline of a directory you trust
python3 integrity_guard.py init /var/www/html -b /etc/integrity/www.json

# 2. Later, check the tree against that baseline
python3 integrity_guard.py check /var/www/html -b /etc/integrity/www.json

# 3. After a legitimate deployment, accept the new state
python3 integrity_guard.py update /var/www/html -b /etc/integrity/www.json
```

### Commands

| Command | Purpose |
| --- | --- |
| `init` | Walk the tree and record the baseline |
| `check` | Compare the tree against the baseline and report drift |
| `update` | Report drift, then accept the current state as the new baseline |

### Options

| Flag | Description | Default |
| --- | --- | --- |
| `-b`, `--baseline` | Baseline file path | `baseline.json` |
| `-e`, `--exclude` | Glob to exclude; repeatable | — |
| `--no-default-excludes` | Drop the built-in exclude list | off |
| `--follow-symlinks` | Follow symbolic links while walking | off |
| `-o`, `--output` | Write the change report as JSON | none |

Logs, caches, `.git`, and `node_modules` are excluded by default so ordinary
runtime churn does not drown the signal.

## Example

```
  Baseline : 2 files, taken 2026-09-15T23:57:43+00:00
  Current  : 2 files
  Changes  : 4

  [HIGH  ] added        www/evil.php
           new file, 6 bytes
  [MEDIUM] deleted      www/config.php
           file no longer present
  [HIGH  ] modified     www/index.html
           content changed (6 -> 14 bytes)
  [MEDIUM] permissions  www/index.html
           mode 0o644 -> 0o777
```

## Running it on a schedule

`check` exits `1` when the tree has drifted and `0` when it is clean, so it
plugs straight into cron:

```cron
0 * * * * /usr/bin/python3 /opt/integrity_guard.py check /var/www/html \
  -b /etc/integrity/www.json -o /var/log/integrity-latest.json \
  || /usr/local/bin/notify-oncall
```

## Design notes

- **Streamed hashing.** Files are hashed in 1 MiB chunks, so a multi-gigabyte
  file costs constant memory.
- **Symlinks are recorded, not followed,** by default — the link *target* is
  part of the baseline, so repointing a symlink is itself detected as a change.
- **Excluded directories are pruned during the walk,** not filtered afterwards,
  so a baseline over a webroot never descends into `node_modules`.
- **Metadata is part of the baseline.** A file whose contents are unchanged but
  whose mode went from `0644` to `0777` is a finding, not a no-op.

## Store the baseline off-host

An attacker with write access to the monitored tree can usually reach the
baseline too. For real deployments, keep the baseline file on separate,
append-only, or read-only storage.

## Tests

37 tests, 97% line coverage. No dependencies. This tool makes no network
calls, and the suite touches nothing outside a temporary directory — log
fixtures and file trees are built and torn down per test.

```bash
# Run the suite
python3 -m unittest discover -s tests -v

# Fail on any leaked socket, file, or database connection
python3 -W error::ResourceWarning -m unittest discover -s tests
```

CI runs the suite on Python 3.10–3.13 on every push, plus a coverage gate and a
3.10 syntax check. See [.github/workflows/tests.yml](.github/workflows/tests.yml).

## License

MIT — see [LICENSE](LICENSE).
