# remove-cisco-agent.sh

Stops/disables Cisco agent services and moves `/opt/cisco` to `/tmp` safely,
with logging and rollback support.

## Features
- `set -euo pipefail` safety
- Timestamped logging to `/tmp/remove-cisco-agent_YYYY-mm-dd_HH-MM-SS.log`
- Colored console output
- Interactive confirmation (`--yes` to skip)
- `--no-rollback` to keep partial state if desired
- `--help` usage
- Functions + unit-like checks after each operation
- Automatic rollback on error (restores services & moved directory)

## Usage
```bash
sudo /usr/local/sbin/remove-cisco-agent.sh
# Non-interactive:
sudo /usr/local/sbin/remove-cisco-agent.sh --yes
# Disable rollback:
sudo /usr/local/sbin/remove-cisco-agent.sh --yes --no-rollback
