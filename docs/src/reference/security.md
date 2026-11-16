# Security notes

Don't use `bas` in production yet, because it isn't ready for production use. Each section below says what one part of `bas` protects against and where its limits are.

## Direct access

Give an agent a machine account that reads only the projects the agent needs, because a program that `bas run` starts receives the values in its environment. Masking keeps a value out of an agent transcript by accident, and it doesn't sandbox the program.

```text
bas run --env API_TOKEN=bas://work/<secret-id> -- agent
  environment of agent     API_TOKEN=value
  stdout and stderr        each value of 4 or more bytes becomes [bas:API_TOKEN]
  not masked               a value written to a file, sent over the network,
                           or printed in another encoding
```

## Credential helpers

Run `bas helper allow` only for references that a credential helper needs, because a program that runs `bas get` can read the raw value. Only `bas helper allow` adds to the list in `helpers.toml`, and it asks you to type a one-time code on the controlling terminal, so a program that can't type on your terminal can't add a reference with `bas`.

```text
on(bas get REFERENCE)
  if stdout is a terminal
    refuse
  if a broker runs on this machine
    ask the broker, which answers only for a [helper.NAME] entry of its policy
      and records the read in its audit log
  else if REFERENCE isn't in helpers.toml
    refuse
  append the reference and the parent process to audit.log, never the value
  print the value
```

An agent that can write files as your user can still edit `helpers.toml`, as it can edit `grants.toml`, so keep agents out of the configuration directory when that matters. A reference of a remote profile still needs approval or a grant on the listener.

On a broker host the local list has no effect, because your user can edit it. There `bas get` reads only `[helper.NAME]` entries of the broker's policy, which change only after a passkey approval.

## The broker

The broker keeps values away from your user only if your user has no way to become root. [Lock down the host](../broker/lock-down.md) lists the steps. The table below lists attacks by an agent that runs as your user, what blocks each one, and what risk is left.

| Attack | Blocked by | Risk left |
|---|---|---|
| Become root with `sudo`, `docker`, or `lxd` | A sudo password, and no membership in `docker` or `lxd` | Capture of the sudo password through shell startup files, any other root path, kernel bugs |
| Decrypt the sealed token | The credential is sealed for the system and readable by root only | None without root |
| Read the broker's memory or environment | A separate user, `ProtectProc=invisible`, `LimitCORE=0`, no swap | None without root |
| Widen access by editing `policy.toml` | The broker uses only the approved copy and shows the diff on the approval page | You approve a diff without reading it |
| Approve its own request | WebAuthn with user verification on your device | A compromised passkey device, or a passkey synced to a machine where an agent runs |
| Show you a false approval page | The configured approval hostname, port 793 below 1024, and an HTTPS reverse proxy controlled only by administrators | A secret typed into a page on another origin |
| Read a token from `gh` or git | The proxy adds the token, and the program never receives it | None found |
| Send a credential to another host | Injection for exact policy hosts only, upstream TLS verified, inner `Host` equal to the `CONNECT` host, port 443 only | A policy host whose response repeats the request headers |
| Forge or delete audit entries | On Linux, journald sets `_SYSTEMD_UNIT`. On macOS, the audit file is owned by root, has the append-only flag, and is unreadable to your user | Root |

### Other local users

On a machine with other local users, add a firewall rule that lets only your user and `bas` connect to ports 3128 and 793, for example an nftables rule that matches `meta skuid`. The proxy and the approval pages don't check the caller's user ID.

| Listener | Linux | macOS |
|---|---|---|
| Proxy, port 3128 | Loopback address, caller not checked | Loopback address, caller not checked, and no firewall rule guards the port |
| Approval pages | Loopback address, port 793, caller not checked | Socket that only `_bas` and root can open |

A local user who can reach the approval port can call the begin endpoint again and again and push out a pending approval's real challenge, so the approver must retry. The local user still can't approve anything.

### Responses from policy hosts

Keep `allow` patterns narrow, because the proxy doesn't inspect responses. A host that echoes request headers can return the credential to the program.

### Pending approvals

A forged answer to an approval gets `403`, and the request stays pending. Pending approvals live in the broker's memory and expire after 15 minutes, and a restart drops them. Each approval accepts only an assertion over a challenge issued for the same request, and the first valid assertion uses up every challenge of the request.

```text
on(POST /a/ID/finish)
  if Origin isn't approvals.origin
    403
  if the assertion doesn't verify against a challenge issued for ID, with user verification
    403, and the request stays pending
  clear every challenge of ID
  apply the change and mark ID approved
```

You can check the rule yourself with the commands below. Replace `ID` with the approval ID that `bas policy edit` prints.

```sh
curl -s -X POST -H 'Origin: https://bas.TAILNET.ts.net' http://127.0.0.1:793/a/ID/begin > /dev/null
curl -s -X POST -H 'Origin: https://bas.TAILNET.ts.net' -H 'content-type: application/json' \
  -d '{"credential":{"id":"AA","rawId":"AA","type":"public-key","extensions":{},"response":{"authenticatorData":"AA","clientDataJSON":"AA","signature":"AA","userHandle":null}}}' \
  http://127.0.0.1:793/a/ID/finish
curl -s --unix-socket /run/bas/broker.sock http://localhost/v1/approvals/ID
```

The second command gets `403` with "no valid assertion", and the third still reports `pending`.

### ssh-agent keys

The ssh-agent refuses ECDSA keys, because their signing code in the library the broker uses isn't constant time (RUSTSEC-2026-0387).

## Agent Access

A paired device can ask for secrets, and each request needs an approval code or a grant. A revocation waits for deliveries that have started, and it can't recall a value already delivered. [Grants](../remote/grants.md) explains the order.

## Dependencies

The advisory check with `cargo-deny` passes with the exceptions that `deny.toml` lists, each with its reason.

| Advisory | Where | Why it is ignored |
|---|---|---|
| `RUSTSEC-2023-0071` | The RSA crate in the Bitwarden SDK | No patched RSA release exists, so the finding stays open |
| `RUSTSEC-2026-0459` | Bundled SQLite in the Bitwarden SDK | `bas` opens no SQLite file |
| `RUSTSEC-2026-0387` | `crypto-bigint`, used for ECDSA by the ssh-agent library | The broker's ssh-agent refuses ECDSA keys |

`cargo deny check licenses` fails, because `deny.toml` doesn't list any allowed licenses yet. The `bas` source is under the MIT license.
