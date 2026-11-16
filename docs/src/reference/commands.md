# Commands

Find the command you need in the tree below, and run `bas <command> --help` when you need the longer description of its options. Commands marked Linux and macOS exist only in those builds.

```text
bas
├── auth      login, status, logout, list
├── find
├── run
├── get
├── helper    allow, list, revoke
├── env       write, run
├── create
├── update
├── doctor
├── tui
├── listen                       Agent Access
├── pair                         Agent Access
├── grant     add, list, revoke  Agent Access
├── broker                       Linux and macOS
├── add                          Linux and macOS
├── rotate                       Linux and macOS
├── policy    edit, show         Linux and macOS
├── audit                        Linux and macOS
├── passkey   add, list          Linux and macOS
└── mcp                          Linux and macOS
```

Commands print references, metadata, and receipts, and only `bas get` prints a secret value. It prints one only for a reference you allowed with `bas helper allow`, or, on a broker host, for a reference in a `[helper.NAME]` entry of the broker's policy.

## Profiles

Sign in once with `bas auth login`, and then use the profile name in every other command. In the tables below, a flag marked required must be on the command line.

| Command | Options | What it does |
|---|---|---|
| `bas auth login [PROFILE]` | `--organization <UUID>`, `--region us\|eu`, `--server-url <URL>`, `--api-url <URL> --identity-url <URL>`, `--stdin`, `--clipboard`, `--from-env` | Signs in with a machine token and saves the profile only after the sign-in succeeds. `PROFILE` defaults to `default`. Without an input flag, it asks for the token in the terminal and hides it. Without an endpoint flag, it tries `bitwarden.com` and then `bitwarden.eu`. |
| `bas auth status <PROFILE>` | | Signs in again and reports the organization and endpoint |
| `bas auth list` | | Lists profiles and paired devices without contacting a server |
| `bas auth logout <PROFILE>` | | Deletes a profile and its stored token. For a direct profile, it also removes its paired devices and revokes its grants. |
| `bas doctor` | `--profile <PROFILE>`, `--broker` (Linux and macOS), `--json` | Reports readiness, offline unless you give `--profile` or `--broker` |
| `bas tui` | `--profile <PROFILE>`, `--broker` (Linux and macOS) | Opens the terminal UI for secrets and projects, and signs in first when the profile doesn't exist. Without `--profile`, it manages the broker's policy with no token whenever the broker answers. `--broker` forces that mode and can't be combined with `--profile`. |

`bas doctor` adds checks for each flag you give, and it changes nothing.

```text
bas doctor
├── offline checks of the configuration, always
├── --profile NAME   signs in to NAME and confirms its organization
└── --broker         Linux and macOS, uses BAS_BROKER_SOCKET or the default socket
    ├── signs and verifies a disposable commit with this repository's Git settings
    ├── reads the broker's status and policy
    └── checks that the broker's machine account sees every reference of its policy
```

It changes no Git ref, setting, or secret, and it reads no secret value. It exits 1 when a check failed, 2 when a check warned and none failed, and 0 otherwise. A warning means `bas` couldn't gather the evidence for a verdict. With `--json`, it prints the result in the shape below instead of text.

```json
{"status": "...", "checks": [{"name": "...", "status": "...", "detail": "...", "evidence": "...", "fix": "..."}]}
```

## Secrets

Use these commands to find references, run programs with them, and write secrets.

| Command | Options | What it does |
|---|---|---|
| `bas find [QUERIES]...` | `--profile <PROFILE>` (required), `--project <UUID>`, `--json` | Lists references whose key contains a query, ignoring case. No query lists every reference. |
| `bas run -- <COMMAND>...` | `--env <NAME=REFERENCE>` (repeat), `--with <NAME>` (repeat, Linux and macOS), and at least one of the two | Runs a program with secrets in its environment, or with broker proxy settings |
| `bas get <REFERENCE>` | | Prints the raw value of an allowed reference with no trailing newline, for credential helpers. Refuses when stdout is a terminal. |
| `bas helper allow <REFERENCE>` | | Lets `bas get` print the reference, after you type a one-time code on the terminal. Refuses on a broker host. |
| `bas helper list` | `--json` | Lists the references `bas get` may print, from the broker's policy on a broker host |
| `bas helper revoke <REFERENCE>` | | Stops `bas get` from printing the reference. Refuses on a broker host. |
| `bas env write <FILE>` | `--env <NAME=REFERENCE>` (required, repeat), `--force` | Writes a reference template. `--force` replaces an existing file. |
| `bas env run <FILE> -- <COMMAND>...` | | Runs a program with the bindings of a template |
| `bas create` | `--profile <PROFILE>`, `--key <KEY>`, `--project <UUID>`, and `--stdin` or `--clipboard`, all required | Creates a secret and prints a JSON receipt |
| `bas update <REFERENCE>` | `--stdin` or `--clipboard` (required) | Replaces the value of a secret and keeps its key, note, and project |

## Agent Access

Use these commands to serve secrets from one machine to a paired device.

| Command | Options | What it does |
|---|---|---|
| `bas listen` | `--profile <PROFILE>` (required), `--relay <URL>` (required), `--allow <SECRET-ID>` (required, repeat), `--pair`, `--peer-name <NAME>` | Serves paired devices until interrupted |
| `bas pair <PROFILE>` | `--relay <URL>` (required) | Pairs with a listener and saves a remote profile |
| `bas grant add` | `--profile <PROFILE>`, `--device <FINGERPRINT>`, `--secret <SECRET-ID>` (repeat), all required | Lets a paired device receive exact secrets without a prompt, and prints the grant as one JSON line |
| `bas grant list` | `--profile <PROFILE>`, `--json` | Lists active and revoked grants, only those of one listener profile with `--profile` |
| `bas grant revoke <GRANT>` | | Revokes a grant and reports only after the revocation is on disk |

## Broker (Linux and macOS)

Use these commands on a machine that runs the broker.

| Command | Options | What it does |
|---|---|---|
| `bas broker` | `--socket <PATH>`, `--ssh-agent-socket <PATH>`, `--config <PATH>`, `--state-dir <PATH>`, `--ca-bundle <PATH>`, `--audit-log <PATH>` (macOS) | Runs the broker, normally as `bas-broker.service` on Linux or `io.github.bjoernaagaard.bas.broker` on macOS |
| `bas broker install` | `--dry-run`, `--organization <ID>`, `--origin <URL>`, `--project <ID>`, `--profile <NAME>`, `--allow-uid <UID>` (repeat), `--region <REGION>`, `--server-url <URL>`, `--api-url <URL>`, `--identity-url <URL>` | Installs the broker on Linux with systemd, or brings an install up to date. It prints its plan, changes only what differs, and asks for the machine token itself. It needs root unless you give `--dry-run`. |
| `bas add <NAME>` | `--host <HOST>` (required), `--allow <METHOD PATH>` (required, repeat), `--header <HEADER>`, `--value <VALUE>` | Proposes a new proxy secret, whose value you type on the approval page. `--header` defaults to `Authorization`, and `--value` defaults to `Bearer {secret}`. |
| `bas rotate <NAME>` | | Replaces a stored value from the approval page, or drops minted `github` or `tailscale` tokens |
| `bas policy edit` | | Opens the policy proposal in an editor, sends it, and waits for the approval |
| `bas policy show` | `--json` | Lists every entry of the active policy and how to use it, without values |
| `bas audit` | `--since <SINCE>`, `--name <NAME>`, `--unit <UNIT>` (Linux), `--json` | Prints the broker's audit entries, from the system journal on Linux and from the broker on macOS. `--since` takes a span such as `30m`, `1h`, or `2d`, and also a `journalctl --since` time on Linux or an RFC 3339 time on macOS. |
| `bas passkey add` | `--replace` | Asks an enrolled passkey to approve enrolling one more. With `--replace`, the passkeys you enroll replace every enrolled passkey. |
| `bas passkey list` | `--json` | Lists the enrolled passkeys by name and the time each was added |
| `bas mcp` | | Serves the broker to an MCP client over stdin and stdout, and stops when stdin closes |

The defaults of `bas broker` match the unit file on Linux and the LaunchDaemon on macOS.

```text
bas broker            Linux                      macOS
  --socket            /run/bas/broker.sock       /var/run/bas/broker.sock
  --ssh-agent-socket  /run/bas/ssh-agent.sock    /var/run/bas/ssh-agent.sock
  --config            /etc/bas/broker.toml       /etc/bas/broker.toml
  --state-dir         /var/lib/bas               /var/db/bas
  --ca-bundle         /run/bas/ca-bundle.pem     /var/run/bas/ca-bundle.pem
  --audit-log         (the journal)              /var/log/bas/audit.jsonl
```

`bas mcp` speaks the Model Context Protocol version 2025-11-25 and offers three tools that only read. No tool can approve, deny, or change a request, and none returns a secret, so a person still approves each request with a passkey on the approval page. The server runs as the user who starts it and talks to the broker at `BAS_BROKER_SOCKET`, or at the default socket.

| Tool | What it returns |
|---|---|
| `policy_entries` | Policy summaries, without secret values or header templates |
| `broker_status` | The pending approvals |
| `approve_pending` | One approval and its link |

## Errors from the parser

When an argument is wrong, `bas` exits with code 2 and doesn't repeat the rejected value, because the value may be a secret.

```text
$ bas run --with
bas: invalid arguments; rejected values are not repeated because they may be secrets. Run `bas --help` or `bas <command> --help`
```
