# Commands

The list below shows every `bas` command and its options. `bas <command> --help` prints the same options with longer descriptions. Commands marked Linux and macOS exist only in those builds.

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
└── passkey   add, list          Linux and macOS
```

Commands print references, metadata, and receipts. Only `bas get` prints a secret value, and only for a reference you allowed with `bas helper allow`, or, on a broker host, a reference in a `[helper.NAME]` entry of the broker's policy.

## Profiles

| Command | Options | What it does |
|---|---|---|
| `bas auth login [PROFILE]` | `--organization <UUID>`, `--region us\|eu`, `--server-url <URL>`, `--api-url <URL> --identity-url <URL>`, `--stdin`, `--clipboard`, `--from-env` | Signs in with a machine token and saves the profile only after the sign-in succeeds. `PROFILE` defaults to `default`. Without an input flag, it asks for the token in the terminal and hides it. |
| `bas auth status <PROFILE>` | | Signs in again and reports the organization and endpoint |
| `bas auth list` | | Lists profiles and paired devices without contacting a server |
| `bas auth logout <PROFILE>` | | Deletes a profile and its stored token. For a direct profile, it also removes its paired devices and revokes its grants. |
| `bas doctor` | `--profile <PROFILE>` | Reports readiness offline, or also signs in to the profile |
| `bas tui` | `--profile <PROFILE>`, `--broker` (Linux and macOS) | Opens the terminal UI for secrets and projects, and signs in first when the profile doesn't exist. Without `--profile`, it manages the broker's policy with no token whenever the broker answers. `--broker` forces that mode |

## Secrets

| Command | Options | What it does |
|---|---|---|
| `bas find [QUERIES]...` | `--profile <PROFILE>` (required), `--project <UUID>`, `--json` | Lists references whose key contains a query, ignoring case |
| `bas run -- <COMMAND>...` | `--env <NAME=REFERENCE>` (repeat), `--with <NAME>` (repeat, Linux and macOS) | Runs a program with secrets in its environment, or with broker proxy settings |
| `bas get <REFERENCE>` | | Prints the raw value of an allowed reference with no trailing newline, for credential helpers. Refuses when stdout is a terminal |
| `bas helper allow <REFERENCE>` | | Lets `bas get` print the reference, after you type a one-time code on the terminal |
| `bas helper list` | `--json` | Lists the references `bas get` may print, from the broker's policy on a broker host |
| `bas helper revoke <REFERENCE>` | | Stops `bas get` from printing the reference |
| `bas env write <FILE>` | `--env <NAME=REFERENCE>` (repeat), `--force` | Writes a reference template |
| `bas env run <FILE> -- <COMMAND>...` | | Runs a program with the bindings of a template |
| `bas create` | `--profile <PROFILE>`, `--key <KEY>`, `--project <UUID>`, and `--stdin` or `--clipboard` | Creates a secret and prints a JSON receipt |
| `bas update <REFERENCE>` | `--stdin` or `--clipboard` | Replaces the value of a secret and keeps its key, note, and project |

## Agent Access

| Command | Options | What it does |
|---|---|---|
| `bas listen` | `--profile <PROFILE>`, `--relay <URL>`, `--allow <SECRET-ID>` (repeat), `--pair`, `--peer-name <NAME>` | Serves paired devices until interrupted |
| `bas pair <PROFILE>` | `--relay <URL>` (required) | Pairs with a listener and saves a remote profile |
| `bas grant add` | `--profile <PROFILE>`, `--device <FINGERPRINT>`, `--secret <SECRET-ID>` (repeat) | Lets a paired device receive exact secrets without a prompt |
| `bas grant list` | `--profile <PROFILE>`, `--json` | Lists active and revoked grants |
| `bas grant revoke <GRANT>` | | Revokes a grant and reports only after the revocation is on disk |

## Broker (Linux and macOS)

| Command | Options | What it does |
|---|---|---|
| `bas broker` | `--socket <PATH>`, `--ssh-agent-socket <PATH>`, `--config <PATH>`, `--state-dir <PATH>`, `--ca-bundle <PATH>`, `--audit-log <PATH>` (macOS) | Runs the broker, normally as `bas-broker.service` on Linux or `io.github.bjoernaagaard.bas.broker` on macOS |
| `bas add <NAME>` | `--host <HOST>`, `--allow <METHOD PATH>` (repeat), `--header <HEADER>`, `--value <VALUE>` | Proposes a new proxy secret, whose value you type on the approval page |
| `bas rotate <NAME>` | | Replaces a stored value from the approval page, or drops minted `github` or `tailscale` tokens |
| `bas policy edit` | | Opens the policy proposal in an editor, sends it, and waits for the approval |
| `bas policy show` | `--json` | Lists every entry of the active policy and how to use it, without values |
| `bas audit` | `--since <SINCE>`, `--name <NAME>`, `--unit <UNIT>` (Linux), `--json` | Prints the broker's audit entries: from the system journal on Linux, from the broker on macOS |
| `bas passkey add` | `--replace` | Asks an enrolled passkey to approve enrolling one more. With `--replace`, the passkeys you enroll replace every enrolled passkey |
| `bas passkey list` | `--json` | Lists the enrolled passkeys by name and the time each was added |

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

## Errors from the parser

When an argument is wrong, `bas` exits with code 2 and doesn't repeat the rejected value, because it may be a secret.

```text
$ bas run --with
bas: invalid arguments; rejected values are not repeated because they may be secrets. Run `bas --help` or `bas <command> --help`
```
