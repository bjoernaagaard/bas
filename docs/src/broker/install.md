# Install the broker

Run the numbered steps below in order as your normal user, from a console or SSH session where no agent is running, so no agent sees the machine token or the enrollment link. On a Mac, follow [Install on macOS](#install-on-macos) instead. Commands that change system files use `sudo`.

The install puts one program, one systemd unit, and a few files owned by root on the machine. It also seals the machine token so that only the broker's service can read it. The files come from `contrib/linux/` in the repository.

```text
contrib/linux/                      installed as
├── bas-broker.service              /etc/systemd/system/bas-broker.service
├── broker.toml.example             /etc/bas/broker.toml
├── ../policy.toml.example          ~/.config/bas/policy.toml (your proposal)
├── shims/
│   ├── gh                          /usr/local/lib/bas/shims/gh
│   └── ssh-keygen                  /usr/local/lib/bas/shims/ssh-keygen
└── ssh_config.d/
    └── 10-bas.conf                 /etc/ssh/ssh_config.d/10-bas.conf
```

## Before you start

Have each item in the table ready before step 1.

| You need | Details |
|---|---|
| A Linux machine | It needs systemd and `systemd-creds`. |
| An HTTPS reverse proxy for approvals | Tailscale Serve is one option. |
| `bas` v0.4.0 or later on Linux, v0.8.1 or later on macOS | Use a release, or build it from source, as [Install bas](../getting-started/install.md) describes. |
| A Secrets Manager machine account for the broker, and an access token for it | Give the account read access to the project that holds the secrets the policy names. Give it write access to the project where `bas add` should create new secrets. |
| A passkey device | A YubiKey, or a phone or password manager that holds passkeys |

```mermaid
flowchart TD
    A[1. Install the program] --> B[2. Create the bas user]
    B --> C[3. Seal the machine token]
    C --> D[4. Install the unit and broker.toml]
    D --> E[5. Start the broker]
    E --> F[6. Publish the approval pages]
    F --> G[7. Enroll the first passkey]
    G --> H[8. Approve a first policy]
    H --> I[9. Put the shims on PATH]
    I --> J[10. Point ssh at the broker]
    J --> K[11. Sign git commits through the broker]
```

## 1. Install the program

Copy the program to `/usr/local/bin/bas`, a path that only root can write, because the unit runs `/usr/local/bin/bas broker`.

```sh
sudo install -o root -g root -m 0755 target/release/bas /usr/local/bin/bas
```

For a release archive, run the command from the extracted directory and replace `target/release/bas` with `bas`. The archive includes the `contrib/linux/` files that the later steps use.

## 2. Create the bas user

Create the system user `bas`, which has no login shell and no home directory of its own. systemd creates `/var/lib/bas` for it on the first start.

```sh
sudo useradd --system --home-dir /var/lib/bas --no-create-home --shell /usr/sbin/nologin bas
```

## 3. Seal the machine token

Paste the machine token at the prompt, and `systemd-creds` encrypts it with a key that only root can read. `systemd-ask-password` hides what you paste. Don't put the token in a file or on a command line.

```sh
sudo install -d -o root -g root -m 0700 /etc/credstore.encrypted
sudo sh -c 'systemd-ask-password -n "Machine token for the bas broker:" \
  | systemd-creds encrypt --name=bws - /etc/credstore.encrypted/bas-bws.cred'
sudo chmod 0600 /etc/credstore.encrypted/bas-bws.cred
```

systemd decrypts the token for the broker's service only, and the broker reads it from the file `bws` in `$CREDENTIALS_DIRECTORY`.

```text
/etc/credstore.encrypted/bas-bws.cred    root, 0600, encrypted
└── LoadCredentialEncrypted=bws:...      in bas-broker.service
    └── $CREDENTIALS_DIRECTORY/bws       decrypted, for the broker's service only
```

## 4. Install the unit and broker.toml

Install the unit and `broker.toml`, then edit `broker.toml` for this machine. The unit runs the broker as `bas`, gives it the sealed token, and allows it only the one capability it needs, which is binding port 793.

```sh
sudo install -o root -g root -m 0644 contrib/linux/bas-broker.service /etc/systemd/system/
sudo install -d -o root -g root -m 0755 /etc/bas
sudo install -o root -g root -m 0644 contrib/linux/broker.toml.example /etc/bas/broker.toml
sudoedit /etc/bas/broker.toml
```

Set the keys in the table. The approval origin is the HTTPS address you will use for approvals.

| Key | Set it to |
|---|---|
| `allow-uids` | Your user ID. Run `id -u` to find it. |
| `organization` in `[profile]` | Your organization ID |
| `project` in `[profile]` | The project where `bas add` creates new secrets |
| `api-url` and `identity-url` in `[profile]` | The endpoints for your region |
| `origin` in `[approvals]` | Such as `https://bas.example.com`. For Tailscale Serve, use `https://bas.TAILNET.ts.net`, where `TAILNET` is the name of your tailnet. |

```diff
-allow-uids = [1000]
+allow-uids = [1000]                     # your uid, from id -u
 [profile]
 name = "home"
-organization = "<organization-id>"
+organization = "<your organization ID>"
-project = "<project-id>"
+project = "<the project for bas add>"
 [approvals]
-origin = "https://bas.<tailnet>.ts.net"
+origin = "https://bas.TAILNET.ts.net"
```

[Files and directories](../reference/files.md) lists every key of `broker.toml`.

## 5. Start the broker

Start the broker and ask it for its status.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now bas-broker
systemctl status bas-broker --no-pager
curl -s --unix-socket /run/bas/broker.sock http://localhost/v1/status
```

The status reply holds the version, the hash of the active policy, and the IDs of pending approvals. Until you approve a first policy, the active policy is empty and allows nothing.

```text
{"version":"0.8.8","policy_hash":"<sha-256 of the policy text>","requests":[]}
```

If the broker doesn't start, `journalctl -u bas-broker -e` shows why, for example a malformed `broker.toml` or a token that Secrets Manager refused.

## 6. Publish the approval pages

Publish the approval pages, which listen on `127.0.0.1:793`, through an HTTPS reverse proxy. Choose the hostname before you enroll a passkey, because passkeys are bound to that hostname. Tailscale is optional, and you need no Tailscale account when you use another reverse proxy.

The WebAuthn relying party ID is the hostname in `approvals.origin`. A passkey enrolled for that hostname can't be used by a page on another hostname.

### Use an existing HTTPS reverse proxy

Forward one HTTPS hostname to `http://127.0.0.1:793` on the broker host.

1. Choose a hostname with a TLS certificate that your approval browser trusts.
2. Configure your reverse proxy to forward requests for that hostname to `http://127.0.0.1:793` on the broker host, and keep paths and query strings as they are.
3. Set `approvals.origin` in `/etc/bas/broker.toml` to that HTTPS address, and restart `bas-broker`.

```text
Approval browser
└── https://bas.example.com
    └── HTTPS reverse proxy on the broker host
        └── http://127.0.0.1:793
```

Keep the reverse proxy configuration and its certificate keys under administrator control. Restrict access with your firewall or private network, and keep the broker listener on loopback.

### Use Tailscale Serve

Publish the pages to your tailnet as the Tailscale Service `svc:bas`.

1. Define the service `svc:bas` on the Services page of the Tailscale admin console, with HTTPS on port 443.
2. Run the command below on the broker machine.
3. Approve the machine as a host of the service in the admin console when it asks.

```sh
sudo tailscale serve --service=svc:bas --https=443 127.0.0.1:793
tailscale serve status
```

```text
https://bas.TAILNET.ts.net (tailnet only) (svc:bas)
|-- / proxy http://127.0.0.1:793
```

## 7. Enroll the first passkey

Open the one-time enrollment link on the device that will approve requests. While no passkey is enrolled, the broker writes the link to `/var/lib/bas/enroll-url`, which only root and the `bas` user can read.

```sh
sudo cat /var/lib/bas/enroll-url
```

| Passkey device | Where you open the link |
|---|---|
| YubiKey | In a browser on a computer with the key plugged in |
| Phone passkey | On the phone |

Name the passkey and choose Create passkey. The page says "Enrolled", and the broker deletes `enroll-url`. To add more passkeys later, run `bas passkey add` and approve with a passkey you already have.

## 8. Approve a first policy

Store your secrets in Secrets Manager, write a policy that names them, and approve the policy with your passkey. The policy says which secrets the proxy may use, for which hosts and requests, and which SSH keys the ssh-agent signs with.

1. Store each secret in Secrets Manager, in the broker's project. For an SSH key, store the OpenSSH private key text, which must be an ed25519 or rsa key without a passphrase.
2. Copy the example policy, and replace each `<secret-id>` with the ID of the secret.
3. Send the policy for approval with `bas policy edit`.

```sh
install -d -m 0700 ~/.config/bas
install -m 0600 contrib/policy.toml.example ~/.config/bas/policy.toml
bas policy edit
```

`bas policy edit` opens the proposal in `$VISUAL` or `$EDITOR`. After you save and quit, it prints the diff and the approval URL, and it waits. Open the URL, check the diff, and approve with your passkey.

```text
$ bas policy edit
--- active
+++ proposed
@@ -1 +1,9 @@
 version = 1
+
+[secret.JINA_API_KEY]
+ref = "bas://home/<secret-id>"
...
Approve with your passkey: https://bas.TAILNET.ts.net/a/<approval-id>
Waiting for approval <approval-id> (it expires in 15 minutes)...
the active policy is now <hash>
```

When the broker can't apply an approved policy, for example because an SSH key in it has a passphrase, `bas policy edit` says so, and the active policy stays as it was. [Policy reference](policy.md) describes every table.

## 9. Put the shims on PATH

Install the `gh` and `ssh-keygen` shims, and put their directory first in `PATH`. A shim is a small script that runs the real program with the broker's settings.

```sh
sudo install -d -o root -g root -m 0755 /usr/local/lib/bas/shims
sudo install -o root -g root -m 0755 contrib/linux/shims/gh contrib/linux/shims/ssh-keygen /usr/local/lib/bas/shims/
```

With mise, add the shims directory to `PATH` in a mise config file, such as `~/.config/mise/conf.d/bas.toml`.

```toml
[env]
_.path = ["/usr/local/lib/bas/shims"]
```

Without mise, put `/usr/local/lib/bas/shims` first in `PATH` in your shell profile. Then check that `command -v gh` prints `/usr/local/lib/bas/shims/gh`.

The `gh` shim runs `gh` through the proxy with the repository of the current directory, so the broker adds a GitHub App token for the same repository. The `ssh-keygen` shim sends git's signing requests to the broker's ssh-agent, as step 11 shows.

```text
gh pr list                                  (you type)
└── /usr/local/lib/bas/shims/gh
    ├── reads OWNER/REPO from git remote get-url origin
    └── runs the real gh with
        HTTPS_PROXY=http://gh:OWNER%2FREPO@127.0.0.1:3128
        SSL_CERT_FILE=/run/bas/ca-bundle.pem
        GH_TOKEN=bas-proxied                (a placeholder, gh needs some token)
```

The `gh` shim makes `gh auth token` fail on purpose, because there is no raw token to print. A tool that asks `gh auth token` for a token, such as mise, falls back to anonymous requests.

## 10. Point ssh at the broker

Install `10-bas.conf`, which tells `ssh` to ask the broker's ssh-agent for every host. `ssh` and git over SSH then use the keys in `[ssh.NAME]` entries with `use = ["auth"]`.

```sh
sudo install -o root -g root -m 0644 contrib/linux/ssh_config.d/10-bas.conf /etc/ssh/ssh_config.d/
SSH_AUTH_SOCK=/run/bas/ssh-agent.sock ssh-add -L
ssh -T git@github.com
```

```text
ssh-ed25519 AAAA... bas:git_signing
ssh-ed25519 AAAA... bas:github
Hi USER! You've successfully authenticated, but GitHub does not provide shell access.
```

The agent lists each key with the comment `bas:NAME`. `/etc/ssh/ssh_config` must include `/etc/ssh/ssh_config.d/*.conf`, which it does by default on Debian and Ubuntu. Remove the old private key files from `~/.ssh`, and keep only the `.pub` files.

## 11. Sign git commits through the broker

Make git sign through the `ssh-keygen` shim with a system setting, and name the public key to sign with in your own git settings.

```sh
sudo git config --system gpg.ssh.program /usr/local/lib/bas/shims/ssh-keygen
install -d -m 0700 ~/.ssh
SSH_AUTH_SOCK=/run/bas/ssh-agent.sock ssh-add -L | grep 'bas:git_signing' > ~/.ssh/git_signing.pub
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/git_signing.pub
git config --global commit.gpgsign true
```

git signs a commit by running `ssh-keygen -Y sign`, which uses `SSH_AUTH_SOCK` and ignores the ssh config. The shim points `SSH_AUTH_SOCK` at the broker.

```text
git commit
└── gpg.ssh.program = /usr/local/lib/bas/shims/ssh-keygen
    └── SSH_AUTH_SOCK=/run/bas/ssh-agent.sock /usr/bin/ssh-keygen -Y sign
        └── the broker's ssh-agent signs with the key in ~/.ssh/git_signing.pub
```

A key with `use = ["sign-git"]` signs only SSH signatures in the `git` namespace, which is what `git commit -S` and `git tag -s` ask for. It can't sign an SSH login.

## Check the install

Run the commands below in a scratch Git repository. The first two need a `JINA_API_KEY` entry in the policy, so use the name of any `[secret.NAME]` entry you have.

```sh
bas run --with JINA_API_KEY -- sh -c 'env | grep -E "^(HTTPS_PROXY|SSL_CERT_FILE)="'
bas run --with NOT_IN_POLICY -- true
git commit --allow-empty -m "signed through the broker" && git log --show-signature -1
bas audit --since 10m
```

```text
HTTPS_PROXY=http://127.0.0.1:3128
SSL_CERT_FILE=/run/bas/ca-bundle.pem
bas: not started: the bas broker denied NOT_IN_POLICY: it is not a proxy entry of the active policy
```

The audit shows one entry for each check.

| Command | Audit entry |
|---|---|
| `bas run --with JINA_API_KEY` | `run` |
| `bas run --with NOT_IN_POLICY` | `deny` |
| `git commit` | `sign` |

## Install on macOS

Run the commands in this section from an admin account, or from a root shell, while no agent runs. On macOS, a LaunchDaemon runs the broker as the role account `_bas`, and the files come from `contrib/macos/`. Steps 8, 10, and 11 above work the same way with `/var/run/bas/` in place of `/run/bas/`.

```text
contrib/macos/                                  installed as
├── io.github.bjoernaagaard.bas.rundir.plist    /Library/LaunchDaemons/io.github.bjoernaagaard.bas.rundir.plist
├── io.github.bjoernaagaard.bas.broker.plist    /Library/LaunchDaemons/io.github.bjoernaagaard.bas.broker.plist
├── broker.toml.example                         /etc/bas/broker.toml
├── ../policy.toml.example                      ~/Library/Application Support/bas/policy.toml (your proposal)
├── shims/gh                                    /usr/local/lib/bas/shims/gh
├── shims/ssh-keygen                            /usr/local/lib/bas/shims/ssh-keygen
└── ssh_config.d/10-bas.conf                    /etc/ssh/ssh_config.d/10-bas.conf
```

### Make your account a standard user

Make the account you work in a standard user before you install anything. While it is an admin, its password is worth root, and root can read the token. An agent that runs as you can capture the password with a fake prompt. It can also wait at a `sudo` prompt for a Touch ID or security key touch you meant for something else.

1. Keep a separate admin account, and type its password only at the login window.
2. Check that `id -Gn` no longer lists `admin` for your account.
3. Remove any `sudo` PAM module or `PATH` entry that your account can write, such as files under `/opt/homebrew`.

### Install the program and create _bas

Install the program and create `_bas` with `dscl`, using ID 450 from the 450 to 499 range for role accounts. Don't use `sysadminctl -addUser -roleAccount`, which on macOS 27 ignores `-UID` and gives `_bas` the next regular UID, such as 502. The first command must print nothing, which means no account or group holds ID 450 yet.

```sh
dscl . -list /Users UniqueID | awk '$2 == 450'; dscl . -list /Groups PrimaryGroupID | awk '$2 == 450'
sudo install -o root -g wheel -m 0755 bas /usr/local/bin/bas
sudo dseditgroup -o create -i 450 -r "bas broker" _bas
sudo dscl . -create /Users/_bas
sudo dscl . -create /Users/_bas UniqueID 450
sudo dscl . -create /Users/_bas PrimaryGroupID 450
sudo dscl . -create /Users/_bas UserShell /usr/bin/false
sudo dscl . -create /Users/_bas NFSHomeDirectory /var/empty
sudo dscl . -create /Users/_bas RealName "bas broker"
sudo dscl . -create /Users/_bas Password '*'
sudo dscl . -create /Users/_bas IsHidden 1
id _bas
```

`id _bas` must start with `uid=450(_bas) gid=450(_bas)`.

### Create the state, token, and log files

Create the state, token, and log files, and paste the machine token at the prompt. `read -s` hides what you paste. Don't put the token in a file of your own or on a command line.

```sh
sudo install -d -o _bas -g _bas -m 0700 /var/db/bas /var/db/bas/credentials
sudo sh -c 'printf "Machine token for the bas broker: "; IFS= read -rs t; echo;
  umask 077; printf %s "$t" > /var/db/bas/credentials/bws'
sudo chown _bas:_bas /var/db/bas/credentials/bws && sudo chmod 0400 /var/db/bas/credentials/bws
sudo install -d -o root -g wheel -m 0755 /var/log/bas
sudo touch /var/log/bas/audit.jsonl /var/log/bas/broker.log
sudo chown root:_bas /var/log/bas/audit.jsonl && sudo chmod 0660 /var/log/bas/audit.jsonl
sudo chflags sappnd /var/log/bas/audit.jsonl
sudo chown _bas:_bas /var/log/bas/broker.log && sudo chmod 0640 /var/log/bas/broker.log
```

The commands leave the files in the state the table shows.

| Path | Owner | Mode | Purpose |
|---|---|---|---|
| `/var/db/bas` | `_bas:_bas` | 0700 | Broker state |
| `/var/db/bas/credentials` | `_bas:_bas` | 0700 | Token directory |
| `/var/db/bas/credentials/bws` | `_bas:_bas` | 0400 | Machine token |
| `/var/log/bas` | `root:wheel` | 0755 | Log directory |
| `/var/log/bas/audit.jsonl` | `root:_bas` | 0660, append only | Audit entries |
| `/var/log/bas/broker.log` | `_bas:_bas` | 0640 | Broker log |

The append-only flag lets the broker add lines and stops anyone but root from changing old ones. Only the broker reads `audit.jsonl`, and `bas audit` asks the broker for it.

### Install broker.toml and load the daemons

Install `broker.toml`, set the same keys as in step 4, and load both daemons. Give each Mac its own approval origin, such as `https://bas-mini.TAILNET.ts.net`, so a passkey never approves a request on the wrong broker.

```sh
sudo install -d -o root -g wheel -m 0755 /etc/bas
sudo install -o root -g wheel -m 0644 contrib/macos/broker.toml.example /etc/bas/broker.toml
sudo install -o root -g wheel -m 0644 contrib/macos/io.github.bjoernaagaard.bas.*.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.bjoernaagaard.bas.rundir.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.bjoernaagaard.bas.broker.plist
curl -s --unix-socket /var/run/bas/broker.sock http://localhost/v1/status
```

If the broker doesn't start, `/var/log/bas/broker.log` says why.

### Publish the approval pages and finish

Publish the approval pages with Tailscale Serve as a separate service for each Mac, then enroll the first passkey from the link that the second command prints. The approval pages listen on `/var/run/bas/approve.sock`, which only `_bas` and root can open, and Tailscale Serve runs as root.

```sh
sudo tailscale serve --service=svc:bas-mini --https=443 unix:/var/run/bas/approve.sock
sudo cat /var/db/bas/enroll-url
```

Finish with the same steps as on Linux.

| Task | How |
|---|---|
| Enroll the first passkey | Open the link as in step 7. |
| Install the `gh` and `ssh-keygen` shims and `10-bas.conf` | Use the files from `contrib/macos/`, as in steps 9 to 11. The macOS `gh` shim reads the broker's certificate bundle from `/var/run/bas/ca-bundle.pem`. |

To remove the broker, run the two commands below, and then delete the files that the tree at the top of this section lists.

```sh
sudo launchctl bootout system/io.github.bjoernaagaard.bas.broker
sudo launchctl bootout system/io.github.bjoernaagaard.bas.rundir
```

## Try the broker without installing it

Run the broker as a transient unit under a throwaway user, and it leaves nothing behind. Stop `bas-broker` first if it runs, because the transient broker uses the same socket and ports as the installed one.

Put the program, a `broker.toml`, and a first `seed.toml` policy in `/dev/shm/basdev`, readable by every user, then run the commands below.

```text
/dev/shm/basdev/          readable by every user
├── bas
├── broker.toml
└── seed.toml             copied to /run/bas/state/policy.toml at start
```

```sh
CRED="$(systemd-ask-password -n 'Machine token:' | sudo systemd-creds encrypt --name=bws - - | tr -d '\n')"
sudo systemd-run --unit=bas-broker-dev --collect -p Type=notify -p DynamicUser=yes \
  -p RuntimeDirectory=bas -p RuntimeDirectoryMode=0755 -p UMask=0077 \
  -p AmbientCapabilities=CAP_NET_BIND_SERVICE -p CapabilityBoundingSet=CAP_NET_BIND_SERVICE \
  -p NoNewPrivileges=yes -p "SetCredentialEncrypted=bws:$CRED" \
  -p "ExecStartPre=/bin/sh -c 'mkdir -p /run/bas/state && cp /dev/shm/basdev/seed.toml /run/bas/state/policy.toml'" \
  /dev/shm/basdev/bas broker --config /dev/shm/basdev/broker.toml --state-dir /run/bas/state
unset CRED
BAS_BROKER_UNIT=bas-broker-dev bas audit
sudo systemctl stop bas-broker-dev && rm -rf /dev/shm/basdev
```
