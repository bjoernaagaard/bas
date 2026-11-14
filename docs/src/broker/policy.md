# Policy reference

The policy is a TOML file that says which credentials the broker may use, and how. The broker uses only the active policy, `/var/lib/bas/policy.toml`, which the `bas` user owns and which changes only after a passkey approves the diff. Your copy, `policy.toml` in your configuration directory (`~/.config/bas` on Linux, `~/Library/Application Support/bas` on macOS), is a proposal that `bas policy edit` sends for approval.

```text
policy.toml
├── version = 1                 required
├── [secret.NAME]               zero or more API keys for the proxy
├── [helper.NAME]               zero or more values that bas get prints
├── [ssh.NAME]                  zero or more SSH keys for the ssh-agent
├── [github]                    optional GitHub App
│   └── [[github.repo]]         one per repository
└── [tailscale]                 optional Tailscale OAuth client
```

The broker refuses a policy with an unknown table or key, so a rule it doesn't understand is never ignored. A refused policy prints the line of the problem.

Every `ref`, `private_key`, `client_id`, and `client_secret` is a reference of the form `bas://PROFILE/SECRET-ID`, where `PROFILE` is the `name` in the `[profile]` table of `/etc/bas/broker.toml`.

## [secret.NAME]

A `[secret.NAME]` entry lets the proxy add a stored value as a header on requests for one host. `NAME` must be a valid environment variable name, and it is the name you pass to `bas run --with`.

```toml
[secret.JINA_API_KEY]
ref = "bas://home/<secret-id>"
delivery = "proxy"
host = "api.jina.ai"
header = "Authorization"
value = "Bearer {secret}"
allow = ["GET /v1/*", "POST /v1/*"]
```

| Key | Required | Meaning |
|---|---|---|
| `ref` | yes | Where the value lives in Secrets Manager |
| `delivery` | yes | Must be `"proxy"`. The broker refuses `"env"`, because it never puts a value in a program's environment. |
| `host` | yes | DNS name without a port. Each host belongs to one entry, and the GitHub and Tailscale hosts belong to their tables. |
| `header` | yes | Header the proxy sets, such as `Authorization` or `x-api-key` |
| `value` | yes | Header value, with `{secret}` exactly once where the stored value goes |
| `allow` | yes | Requests the proxy lets through, as `"METHOD /path/glob"` |

## [helper.NAME]

A `[helper.NAME]` entry lets `bas get` print one stored value, for a tool that reads a secret from a command's stdout, such as a `"!bas get ..."` key in pi's config or a git credential helper. On a broker host, `bas get` asks the broker, and the broker answers only for references in these entries. `NAME` must be a valid environment variable name.

```toml
[helper.CLIPROXY_MANAGEMENT_KEY]
ref = "bas://home/<secret-id>"
```

| Key | Required | Meaning |
|---|---|---|
| `ref` | yes | Where the value lives in Secrets Manager |

A helper entry is the one way a value leaves the broker. Any process of a user in `allow-uids` can read it with `bas get`, agents included, so add an entry only for a value you accept that they can read. The broker writes a `helper` audit entry for each read, and a `deny` entry for a reference without an entry.

## Allow patterns

An `allow` or `api_allow` entry is an HTTP method, a space, and a path pattern. In the path, `*` matches any run of characters, including `/`. A request must match one entry, and every other request gets `403` and a `deny` entry in the journal.

```text
"GET /v1/*"        matches GET /v1/models and GET /v1/a/b
                   doesn't match POST /v1/models or GET /v2/models
"POST /v1/embeddings"
                   matches only POST /v1/embeddings, with any query string
```

The proxy never matches a path with `.` or `..` segments, a backslash, or an encoded dot, slash, or backslash, because the host could read such a path differently from the proxy.

## [ssh.NAME]

An `[ssh.NAME]` entry gives the ssh-agent one key. The key must be an ed25519 or rsa OpenSSH private key without a passphrase. The agent refuses ECDSA keys, because their signing code in the library the broker uses isn't constant time (RUSTSEC-2026-0387). `NAME` may hold letters, digits, `_`, and `-`, and the agent lists the key with the comment `bas:NAME`.

```toml
[ssh.git_signing]
ref = "bas://home/<secret-id>"
use = ["sign-git"]
```

| `use` value | What the key may sign |
|---|---|
| `"sign-git"` | SSH signatures in the `git` namespace, which `git commit -S` and `git tag -s` ask for |
| `"auth"` | Everything else an SSH client signs, which is a login |

A key may list both. A client of the agent can list keys and ask for signatures, and it can't add, remove, or export keys.

## [github]

The `[github]` table lets the proxy mint GitHub App installation tokens. [Set up a GitHub App](github-app.md) shows how to create the App.

```toml
[github]
app_id = 123456
private_key = "bas://home/<secret-id>"
user_token = "bas://home/<secret-id>"

[[github.repo]]
name = "OWNER/REPO"
installation_id = 7654321
permissions = { contents = "write", pull_requests = "write", issues = "write", actions = "read" }
```

| Key | Meaning |
|---|---|
| `app_id` | The App's ID |
| `private_key` | Where the App's RSA private key, in PEM, lives |
| `user_token` | Optional. Where a GitHub user token lives, such as a fine-grained personal access token. The proxy adds it only to requests that name no repository. |
| `[[github.repo]]` `name` | `OWNER/REPO`. Each repository may appear once. |
| `[[github.repo]]` `installation_id` | The installation of the App that covers the repository |
| `[[github.repo]]` `permissions` | Permissions each token asks for, within the App's permissions |

With a `[github]` table, the proxy handles `api.github.com`, `uploads.github.com`, and `github.com`. Each token covers one repository and lasts one hour, and the broker reuses it until five minutes before it expires.

Some requests name no repository, such as `gh auth status`, `gh api user`, or a GraphQL `viewer { login }` query. An App token can't answer them, so without `user_token` the proxy refuses them. With `user_token`, the proxy reads the token from Secrets Manager for each such request and adds it, and the program never sees it. A request that names a repository always gets an App token, and a repository missing from `[[github.repo]]` stays refused.

## [tailscale]

The `[tailscale]` table lets the proxy mint Tailscale API access tokens. [Set up a Tailscale OAuth client](tailscale.md) shows how to create the client.

```toml
[tailscale]
client_id = "bas://home/<secret-id>"
client_secret = "bas://home/<secret-id>"
scopes = ["devices:core:read"]
api_allow = ["GET /api/v2/tailnet/-/devices"]
```

| Key | Meaning |
|---|---|
| `client_id`, `client_secret` | Where the OAuth client's ID and secret live, as two secrets |
| `scopes` | Scopes each token asks for |
| `api_allow` | Requests to `api.tailscale.com` the proxy lets through, as allow patterns |

## What happens on approval

When you approve a policy change, the broker loads every SSH key in the new policy, writes the policy file, makes it active, and drops all minted tokens. If a key can't be loaded, nothing changes, and `bas policy edit` prints the reason.

```text
on(approve policy change)
  if the active policy changed since the request
    fail: run bas policy edit again
  parse the new policy
  load every [ssh.NAME] key from Secrets Manager
    on failure: keep the old policy, report the key's name
  write /var/lib/bas/policy.toml
  make it active, swap the ssh keys, drop minted tokens
  write a policy entry to the journal
```
