# Broker socket replies

`bas` and `bas tui` talk to the broker over its unix socket with HTTP and JSON. This
page describes the replies that clients read to show the broker's state. A client and a
broker of different versions must keep working together, so these replies are a stable
contract.

## Compatibility rules

- A reply only gains fields. No field is removed or renamed, and no field changes type.
- A client ignores fields it does not know.
- A field added after 0.8.6 may be missing from an older broker's reply. A client treats a
  missing field as empty.
- An entry `kind` that a client does not know is shown by its generic fields (`name`,
  `hint`, `about`, `facts`, `use`, `references`), never refused.

## GET /v1/status

```json
{
  "version": "0.8.7",
  "policy_hash": "234a60d414c9...",
  "requests": [
    {
      "id": "8f0c...",
      "kind": "rotate",
      "subject": "JINA_API_KEY",
      "peer_uid": 1000,
      "created_at": "2026-11-14T13:25:58Z",
      "expires_in": 840,
      "url": "https://.../a/8f0c..."
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `version` | Version of the running broker. |
| `policy_hash` | SHA-256 of the active policy text, in lowercase hex. It changes when the policy changes. |
| `requests` | Requests that wait for a passkey approval. `kind` is `add`, `rotate`, `policy`, or `passkey`. |

## GET /v1/policy

```json
{
  "hash": "234a60d414c9...",
  "toml": "version = 1\n...",
  "entries": [
    {
      "kind": "secret",
      "name": "JINA_API_KEY",
      "hint": "api.jina.ai",
      "about": [
        "The broker adds this key to requests to api.jina.ai.",
        "It refuses every other request, and the program never sees the key."
      ],
      "facts": [{ "label": "Allowed", "value": "POST /v1/*" }],
      "use": "bas run --with JINA_API_KEY -- CMD",
      "references": [{ "label": "", "value": "bas://home/<secret-id>" }],
      "details": [
        { "label": "ref", "value": "bas://home/<secret-id>" },
        { "label": "host", "value": "api.jina.ai" }
      ]
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `hash` | SHA-256 of `toml`, in lowercase hex. |
| `toml` | The active policy text, as `bas policy edit` starts from it. |
| `entries` | The broker's own description of each entry, added after 0.8.6. A client shows these instead of reading `toml`, so it never needs to know the policy format of a newer broker. When `entries` is missing, the broker is 0.8.6 or older, and the client reads `toml` itself. |

Each entry has these fields. It names where values live, never a value.

| Field | Meaning |
| --- | --- |
| `kind` | `secret` (an API key the proxy adds), `helper` (a value `bas get` prints), `ssh`, `github`, or `tailscale`. Newer brokers may send other kinds. |
| `name` | The policy name, which `bas rotate` takes. |
| `hint` | A few words for a list row, such as the host an API key is sent to. |
| `about` | Sentences that say what the entry lets a program do. |
| `facts` | The entry's rules in plain words, as label and value pairs in order. |
| `use` | How a program uses the entry. |
| `references` | The `bas://` references of the stored values. A label names each one when there are several. |
| `details` | The entry's policy settings by their keys, as `bas policy show --json` prints them. |

## GET /v1/passkeys

```json
{ "passkeys": [{ "label": "laptop", "added": "2026-11-14T13:25:58Z" }] }
```

The enrolled passkeys, oldest first, without their keys. An empty list means no passkey
can approve a change yet.
