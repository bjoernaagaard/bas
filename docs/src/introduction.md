# Introduction

`bas` lets a coding agent use secrets from Bitwarden Secrets Manager without printing them, and you start with [Install bas](getting-started/install.md).

The agent works with references of the form `bas://<profile>/<secret-id>`, and `bas` puts the matching values into the environment of the program the agent runs. `bas` uses Bitwarden Secrets Manager only, and it doesn't use Bitwarden Password Manager.

`bas` is for a person who runs coding agents on their own machines and keeps API keys, SSH keys, and service tokens in Secrets Manager. It isn't ready for production use.

## Choose direct access or the broker

Use the broker when agents must never read a raw value, and use direct access on any other machine, including Windows.

```mermaid
flowchart LR
    subgraph direct[Direct access]
        A1[Agent] -->|bas run --env| B1[bas]
        B1 -->|secret values in the environment| P1[Program]
    end
    subgraph broker[Broker on Linux or macOS]
        A2[Agent] -->|bas run --with| B2[bas]
        B2 -->|proxy settings only| P2[Program]
        P2 -->|HTTPS| X[bas broker]
        X -->|request with the credential added| API[API host]
    end
    B1 --> SM[(Bitwarden Secrets Manager)]
    X --> SM
```

With direct access, `bas run` reads each referenced secret and starts the program with the values in its environment, so the program and any agent that controls it can read the values. With the broker, a separate system user holds every credential, and the program gets only proxy settings, an ssh-agent socket, and short-lived tokens that the broker adds to its requests.

| Question | Direct access | Broker |
|---|---|---|
| Where does the machine token live? | In your OS credential store, or in `BWS_ACCESS_TOKEN` | On Linux, sealed for one systemd service that runs as its own user. On macOS, in a file that only the `_bas` account can read. |
| Can the program read the value? | Yes | No |
| Which platforms? | Linux, macOS, and Windows | Linux with systemd, and macOS |
| Who approves a new secret? | Nobody. The machine account's project access decides. | You, with a passkey or a YubiKey |

On a host you have locked down, as [Lock down the host](broker/lock-down.md) describes, no program you run can read a raw value, as long as the policy hosts don't send credentials back in their responses.

A third way, Agent Access, lets a remote machine that holds no token ask a trusted machine for each secret. It is experimental, and [Pair a remote machine with Agent Access](remote/agent-access.md) describes it.

## Where to start

Read [Install bas](getting-started/install.md) and then [Sign in with an access token](getting-started/first-run.md).

```text
on(start)
  read Install bas
  read Sign in with an access token
  if agents run unattended on a Linux or macOS machine
    read How the broker works
```

The rest of the site follows the sections below, and [How the broker works](broker/overview.md) opens the broker section.

```text
docs
├── Getting started        install, sign in, find, run, create, update
├── The credential broker  install and daily use on Linux and macOS
├── Remote machines        Agent Access and grants
├── Other platforms        macOS and Windows
└── Reference              commands, exit codes, files, variables, security
```
