# Policy reference

Look up each table and key of `policy.toml` here, then change your copy with `bas policy edit` and approve the diff with a passkey. The policy says which credentials the broker may use and how.

The broker uses only the active policy, and your copy is a proposal that `bas policy edit` sends for approval.

| File | Path | Who changes it |
|---|---|---|
| Active policy on Linux | `/var/lib/bas/policy.toml` | The broker, after a passkey approves the diff. The `bas` user owns it, with mode `0600`. |
| Active policy on macOS | `/var/db/bas/policy.toml` | The broker, after a passkey approves the diff |
| Proposal on Linux | `~/.config/bas/policy.toml`, or `$BAS_CONFIG_DIR/policy.toml` | You |
| Proposal on macOS | `~/Library/Application Support/bas/policy.toml`, or `$BAS_CONFIG_DIR/policy.toml` | You |

```text
policy.toml
├── version = 1                 required, and must be 1
├── [secret.NAME]               zero or more API keys for the proxy
├── [helper.NAME]               zero or more values that bas get prints
├── [ssh.NAME]                  zero or more SSH keys for the ssh-agent
├── [github]                    optional GitHub App
│   └── [[github.repo]]         zero or more, one per repository
└── [tailscale]                 optional Tailscale OAuth client
```

The broker refuses a policy with an unknown table or key, so it never ignores a rule it doesn't understand. A refused policy prints the line of the problem.

Every `ref`, `private_key`, `user_token`, `client_id`, and `client_secret` is a reference of the form `bas://PROFILE/SECRET-ID`. `PROFILE` must be the `name` in the `[profile]` table of `/etc/bas/broker.toml`, and the broker refuses any other profile.

The names `github` and `tailscale` belong to the `[github]` and `[tailscale]` tables, so a `[secret.NAME]` or `[helper.NAME]` entry can't use them.

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
| `host` | yes | DNS name without a port, with only letters, digits, `-`, and `.`. The broker compares it in lowercase. Each host belongs to one entry, and the GitHub and Tailscale hosts belong to their tables. |
| `header` | yes | A valid HTTP header name that the proxy sets, such as `Authorization` or `x-api-key` |
| `value` | yes | Header value, with `{secret}` exactly once where the stored value goes |
| `allow` | yes | Requests the proxy lets through, as [allow patterns](#allow-patterns) |

## [helper.NAME]

A `[helper.NAME]` entry lets `bas get` print one stored value, for a tool that reads a secret from a command's stdout, such as a `"!bas get ..."` key in pi's config or a git credential helper. On a broker host, `bas get` asks the broker, and the broker answers only for references in these entries. `NAME` must be a valid environment variable name.

```toml
[helper.CLIPROXY_MANAGEMENT_KEY]
ref = "bas://home/<secret-id>"
```

| Key | Required | Meaning |
|---|---|---|
| `ref` | yes | Where the value lives in Secrets Manager |

A helper entry is the one way a value leaves the broker. Any process of a user in `allow-uids` of `/etc/bas/broker.toml` can read the value with `bas get`, agents included, so add an entry only for a value you accept that they can read.

```text
on(bas get REF)
  if REF is the ref of a [helper.NAME] entry
    print the value
    write a helper audit entry
  else
    refuse with 403
    write a deny audit entry
```

## Allow patterns

An `allow` or `api_allow` entry is an HTTP method, one space, and a path pattern that starts with `/`. In the path, `*` matches any run of characters, including `/`. A request must match one entry, and every other request gets `403` and a `deny` audit entry.

```text
"GET /v1/*"        matches GET /v1/models and GET /v1/a/b
                   doesn't match POST /v1/models or GET /v2/models
"POST /v1/embeddings"
                   matches only POST /v1/embeddings, with any query string
```

The proxy never matches a path with `.` or `..` segments, a backslash, or an encoded dot, slash, or backslash, because the host could read such a path differently from the proxy.

```text
GET /v1/../admin       never matches
GET /v1/%2e%2e/admin   never matches
```

## [ssh.NAME]

An `[ssh.NAME]` entry gives the ssh-agent one key, which must be an ed25519 or rsa OpenSSH private key without a passphrase. `NAME` may hold letters, digits, `_`, and `-`, and the agent lists the key with the comment `bas:NAME`.

```toml
[ssh.git_signing]
ref = "bas://home/<secret-id>"
use = ["sign-git"]
```

| Key | Required | Meaning |
|---|---|---|
| `ref` | yes | Where the private key lives in Secrets Manager |
| `use` | yes | `"sign-git"`, `"auth"`, or both, and at least one |

| `use` value | What the key may sign |
|---|---|
| `"sign-git"` | SSH signatures in the `git` namespace, which `git commit -S` and `git tag -s` ask for |
| `"auth"` | Everything else an SSH client signs, which is a login |

The agent refuses ECDSA keys, because their signing code in the library the broker uses isn't constant time (RUSTSEC-2026-0387). A client of the agent can list keys and ask for signatures, and it can't add, remove, or export keys.

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

| Key | Required | Meaning |
|---|---|---|
| `app_id` | yes | The App's ID |
| `private_key` | yes | Where the App's RSA private key, in PEM, lives |
| `user_token` | no | Where a GitHub user token lives, such as a fine-grained personal access token. The proxy adds it only to requests that name no repository. |
| `[[github.repo]]` `name` | yes | `OWNER/REPO`, with letters, digits, `-`, `_`, and `.` in each part. Each repository may appear once, compared in lowercase. |
| `[[github.repo]]` `installation_id` | yes | The installation of the App that covers the repository |
| `[[github.repo]]` `permissions` | no | Permissions each token asks for, within the App's permissions. Each permission needs a level, such as `"read"`. |

With a `[github]` table, the proxy handles `api.github.com`, `uploads.github.com`, and `github.com`, and on `github.com` it allows only git's HTTPS paths. Each token covers one repository and lasts one hour, and the broker reuses it until five minutes before it expires.

```text
on(request to a GitHub host)
  find the repository in the path, /repos/OWNER/REPO/... or /OWNER/REPO.git/...,
    or in the proxy user, as in HTTPS_PROXY=http://gh:OWNER%2FREPO@127.0.0.1:3128
  if a repository is named
    if it is in [[github.repo]]
      add an App token for that repository
    else
      refuse
  else if user_token is set
    read user_token from Secrets Manager and add it
  else
    refuse
```

Some requests name no repository, such as `gh auth status`, `gh api user`, or a GraphQL `viewer { login }` query, and an App token can't answer them. The proxy reads `user_token` from Secrets Manager for each such request, and the program never sees it.

## [tailscale]

The `[tailscale]` table lets the proxy mint Tailscale API access tokens for `api.tailscale.com`. [Set up a Tailscale OAuth client](tailscale.md) shows how to create the client.

```toml
[tailscale]
client_id = "bas://home/<secret-id>"
client_secret = "bas://home/<secret-id>"
scopes = ["devices:core:read"]
api_allow = ["GET /api/v2/tailnet/-/devices"]
```

| Key | Required | Meaning |
|---|---|---|
| `client_id`, `client_secret` | yes | Where the OAuth client's ID and secret live, as two secrets |
| `scopes` | yes | Scopes each token asks for |
| `api_allow` | yes | Requests to `api.tailscale.com` the proxy lets through, as [allow patterns](#allow-patterns) |

## What happens on approval

When you approve a policy change, the broker makes the new policy active only if it can load every SSH key in it. If a key can't be loaded, nothing changes, and `bas policy edit` prints the reason.

```text
on(approve policy change)
  if the active policy changed since the request
    fail, and you run bas policy edit again
  parse the new policy
  load every [ssh.NAME] key from Secrets Manager
    on failure, keep the old policy and report the key's name
  write the policy file in the state directory
  make it active, swap the ssh keys, drop minted tokens
  write a policy audit entry
```
