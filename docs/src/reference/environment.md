# Environment variables

Set a variable from the first table to change where `bas` finds its files, token, broker, or editor. The other sections list what `bas run` removes from a program's environment and what `bas run --with` adds.

## Variables bas reads

| Variable | Read by | Meaning |
|---|---|---|
| `BAS_CONFIG_DIR` | every command | Absolute path of the configuration directory, outside every Git repository |
| `BAS_STATE_DIR` | `bas run`, `bas env run`, `bas get` | Absolute path of the directory for `audit.log` |
| `BWS_ACCESS_TOKEN` | profiles made with `--from-env` | The machine token, read at each use |
| `BAS_BROKER_SOCKET` | `bas run --with`, `get`, `helper`, `add`, `rotate`, `policy`, `passkey`, `tui`, `audit`, `mcp`, `doctor --broker` | Path of the broker socket, instead of `/run/bas/broker.sock` on Linux or `/var/run/bas/broker.sock` on macOS |
| `BAS_BROKER_UNIT` | `bas audit` on Linux | Broker unit to read, instead of `bas-broker.service` |
| `VISUAL`, `EDITOR` | `bas policy edit` | Editor for the proposal, `vi` when neither is set |
| `CREDENTIALS_DIRECTORY` | `bas broker` | Set by systemd. The broker reads the machine token from the file `bws` in the directory. |

## Variables bas run removes

`bas run` and `bas env run` remove `BWS_ACCESS_TOKEN` and `AAC_TOKEN` from the program's environment, so the program can't use the machine token or an Agent Access token of the caller. The program inherits every other variable.

```diff
 environment of bas run
-BWS_ACCESS_TOKEN=...
-AAC_TOKEN=...
 PATH=...
 HOME=...
+API_TOKEN=value              with --env API_TOKEN=bas://work/<secret-id>
```

## Variables bas run --with sets

`bas run --with` points the program's HTTPS clients at the broker's proxy and its certificate bundle. The values below are the Linux defaults. On macOS the bundle is `/var/run/bas/ca-bundle.pem`.

```text
HTTPS_PROXY          http://127.0.0.1:3128
https_proxy          http://127.0.0.1:3128
SSL_CERT_FILE        /run/bas/ca-bundle.pem
CURL_CA_BUNDLE       /run/bas/ca-bundle.pem
REQUESTS_CA_BUNDLE   /run/bas/ca-bundle.pem
NODE_EXTRA_CA_CERTS  /run/bas/ca-bundle.pem
GIT_SSL_CAINFO       /run/bas/ca-bundle.pem
```

Go programs on macOS, `gh` among them, ignore `SSL_CERT_FILE`, so they can't use the proxy through `bas run --with`.

## Variables the shims set

The `gh` and `ssh-keygen` shims in `/usr/local/lib/bas/shims` set their variables and then start the real program.

| Shim | Variable | Value |
|---|---|---|
| `gh` | `HTTPS_PROXY` | The proxy, with the repository of the current directory in the proxy user |
| `gh` | `SSL_CERT_FILE` | `/run/bas/ca-bundle.pem` on Linux, `/var/run/bas/ca-bundle.pem` on macOS |
| `gh` | `GH_TOKEN` | `bas-proxied`, a placeholder, because `gh` refuses to run without a token |
| `ssh-keygen` | `SSH_AUTH_SOCK` | `/run/bas/ssh-agent.sock` on Linux, `/var/run/bas/ssh-agent.sock` on macOS |
