# Files and directories

Find the path you need in the trees and tables below, with its owner, mode, and what it holds. `bas` keeps its settings in your configuration directory and its run log in your state directory. The broker adds files owned by root under `/etc` and `/usr/local`, and files of its own under `/var/lib/bas` and `/run/bas`.

## Files of your user

Your configuration directory has mode 0700 and must sit outside every Git repository. `BAS_CONFIG_DIR` and `BAS_STATE_DIR` move the two directories.

```text
~/.config/bas/              BAS_CONFIG_DIR, mode 0700, outside every Git repository
├── config.toml             profiles and paired device fingerprints
├── grants.toml             grants for paired devices
├── helpers.toml            references that bas get may print
├── policy.lock             orders changes to grants, helpers, and profiles
└── policy.toml             broker policy proposal, on a broker host

~/.local/state/bas/         BAS_STATE_DIR
└── audit.log               one JSON line per bas run binding or bas get read, never a value
```

The default directories depend on the platform.

| Platform | Configuration directory | State directory |
|---|---|---|
| Linux | `~/.config/bas` | `~/.local/state/bas` |
| macOS | `~/Library/Application Support/bas` | `~/Library/Application Support/bas` |
| Windows | `%APPDATA%\bas` | `%LOCALAPPDATA%\bas` |

Machine tokens and Agent Access keys live in the OS credential store, and never in the configuration or state directory.

## Files of the broker

The broker's files on Linux are in the table below.

| Path | Owner and mode | Holds |
|---|---|---|
| `/usr/local/bin/bas` | root, 0755 | The program, for the CLI and the broker |
| `/etc/systemd/system/bas-broker.service` | root, 0644 | The unit |
| `/etc/bas/broker.toml` | root, 0644 | Settings for this machine |
| `/etc/credstore.encrypted/bas-bws.cred` | root, 0600 | The sealed machine token |
| `/usr/local/lib/bas/shims/gh`, `ssh-keygen` | root, 0755 | Shims, which hold no secrets |
| `/etc/ssh/ssh_config.d/10-bas.conf` | root, 0644 | Points `ssh` at the broker's agent |
| `/etc/gitconfig` | root, 0644 | `gpg.ssh.program` for commit signing |
| `/var/lib/bas/policy.toml` | bas, 0600 | The active policy |
| `/var/lib/bas/passkeys.json` | bas, 0600 | Public keys of the enrolled passkeys |
| `/var/lib/bas/enroll-url` | bas, 0600 | The first enrollment link, while no passkey is enrolled |
| `/var/lib/bas/ca.key`, `ca.pem` | bas, 0600 and 0644 | The proxy's certificate authority |
| `/run/bas/broker.sock` | bas, 0666 | The socket API, caller uid checked |
| `/run/bas/ssh-agent.sock` | bas, 0666 | The ssh-agent, caller uid checked |
| `/run/bas/ca-bundle.pem` | bas, 0644 | The system roots plus the proxy's authority |

On macOS the broker runs as the role account `_bas`, and the files in the table below take the place of their Linux counterparts. Every other path matches Linux.

| Path | Owner and mode | Holds |
|---|---|---|
| `/Library/LaunchDaemons/io.github.bjoernaagaard.bas.broker.plist`, `io.github.bjoernaagaard.bas.rundir.plist` | root, 0644 | The broker daemon, and the daemon that makes `/var/run/bas` at boot |
| `/var/db/bas/` | _bas, 0700 | The active policy, passkeys, enrollment link, and proxy authority |
| `/var/db/bas/credentials/bws` | _bas, 0400 | The machine token |
| `/var/log/bas/audit.jsonl` | root:_bas, 0660, `sappnd` flag | The audit record, which only the broker reads and which only grows |
| `/var/log/bas/broker.log` | _bas, 0640 | The broker's warnings and start errors |
| `/var/run/bas/broker.sock`, `ssh-agent.sock` | _bas, 0666 | The socket API and the ssh-agent, caller uid checked |
| `/var/run/bas/approve.sock` | _bas, 0600 | The approval pages, for `tailscale serve`, which runs as root |
| `/var/run/bas/ca-bundle.pem` | _bas, 0644 | The system roots plus the proxy's authority |

## broker.toml

`/etc/bas/broker.toml` holds the settings that belong to one machine, and it never syncs. `contrib/linux/broker.toml.example` and `contrib/macos/broker.toml.example` are commented copies, and the file looks like the example below.

```toml
allow-uids = [1000]
# proxy = "127.0.0.1:3128"

[profile]
name = "home"
organization = "<organization-id>"
api-url = "https://api.bitwarden.com"
identity-url = "https://identity.bitwarden.com"
project = "<project-id>"

[approvals]
listen = "127.0.0.1:793"
origin = "https://bas.<tailnet>.ts.net"
```

| Key | Required | Default | Meaning |
|---|---|---|---|
| `allow-uids` | yes | | User IDs that may use the socket API and the ssh-agent |
| `proxy` | no | `127.0.0.1:3128` | Address of the proxy, which must be a loopback address |
| `[profile]` `name` | yes | | Profile name used in policy references |
| `[profile]` `organization` | yes | | Organization ID of the machine token |
| `[profile]` `api-url`, `identity-url` | yes | | Secrets Manager endpoints |
| `[profile]` `project` | no | | Project where `bas add` creates secrets. Without it, `bas add` is refused. |
| `[approvals]` `listen` | no | `127.0.0.1:793` on Linux, `unix:/var/run/bas/approve.sock` on macOS | Where the approval pages listen, as a loopback address, or as `unix:` and an absolute path for a socket with mode 0600 |
| `[approvals]` `origin` | yes | | HTTPS origin of the approval pages, with no path, such as `https://bas.TAILNET.ts.net` |
