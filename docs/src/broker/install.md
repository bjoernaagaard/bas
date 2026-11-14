# Install the broker

The install puts one program, one systemd unit, and a few root-owned files on the machine, and it seals the machine token so that only the broker's service can read it. The files come from `contrib/linux/` in the repository. Run these steps as your normal user, from a console or SSH session where no agent is running, so no agent sees the token or the enrollment link. Commands that change system files use `sudo`.

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

You need the following:

- A Linux machine with systemd and `systemd-creds`, and an HTTPS reverse proxy for approvals. Tailscale Serve is one option.
- `bas` v0.4.0 or later on Linux, v0.8.1 or later on macOS, from a release or built from source, as [Install bas](../getting-started/install.md) describes.
- A Secrets Manager machine account for the broker and an access token for it. Give the account read access to the project that holds the secrets the policy names, and write access to the project where `bas add` should create new secrets.
- A passkey device, such as a YubiKey, or a phone or password manager that holds passkeys.

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

Copy the program to a path that only root can write. The unit runs `/usr/local/bin/bas broker`. For a release archive, run the command from the extracted directory and replace `target/release/bas` with `bas`. The archive includes the `contrib/linux/` files used below.

```sh
sudo install -o root -g root -m 0755 target/release/bas /usr/local/bin/bas
```

## 2. Create the bas user

The broker runs as a system user with no login shell and no home directory of its own. systemd creates `/var/lib/bas` for it on the first start.

```sh
sudo useradd --system --home-dir /var/lib/bas --no-create-home --shell /usr/sbin/nologin bas
```

## 3. Seal the machine token

`systemd-creds` encrypts the token with a key that only root can read, and systemd decrypts it for the broker's service only. The broker reads the decrypted token from the file `bws` in `$CREDENTIALS_DIRECTORY`.

```sh
sudo install -d -o root -g root -m 0700 /etc/credstore.encrypted
sudo sh -c 'systemd-ask-password -n "Machine token for the bas broker:" \
  | systemd-creds encrypt --name=bws - /etc/credstore.encrypted/bas-bws.cred'
sudo chmod 0600 /etc/credstore.encrypted/bas-bws.cred
```

`systemd-ask-password` hides what you paste. Don't put the token in a file or on a command line.

## 4. Install the unit and broker.toml

The unit runs the broker as `bas`, gives it the sealed token, and allows it only the one capability it needs, which is binding port 793. `broker.toml` holds the settings for the broker machine.

```sh
sudo install -o root -g root -m 0644 contrib/linux/bas-broker.service /etc/systemd/system/
sudo install -d -o root -g root -m 0755 /etc/bas
sudo install -o root -g root -m 0644 contrib/linux/broker.toml.example /etc/bas/broker.toml
sudoedit /etc/bas/broker.toml
```

In `broker.toml`, set your user ID in `allow-uids` (run `id -u` to find it), the organization ID, the project ID, the endpoints for your region, and the approval origin. The origin is the HTTPS address you will use for approvals, such as `https://bas.example.com`. For Tailscale Serve, use `https://bas.TAILNET.ts.net`, where `TAILNET` is the name of your tailnet.

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

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now bas-broker
systemctl status bas-broker --no-pager
curl -s --unix-socket /run/bas/broker.sock http://localhost/v1/status
```

The status reply holds the version, the hash of the active policy, and the IDs of pending approvals. Until you approve a first policy, the active policy is empty and allows nothing.

```text
{"version":"0.8.5","policy_hash":"<sha-256 of the policy text>","requests":[]}
```

If the broker doesn't start, `journalctl -u bas-broker -e` shows why, for example a malformed `broker.toml` or a token that Secrets Manager refused.

## 6. Publish the approval pages

The approval pages listen on `127.0.0.1:793` and need an HTTPS reverse proxy. Tailscale is optional, and no Tailscale account is needed when you use another reverse proxy.

### Use an existing HTTPS reverse proxy

First, choose a hostname with a TLS certificate trusted by your approval browser. Second, configure your reverse proxy to forward requests for that hostname to `http://127.0.0.1:793` on the broker host, preserving paths and query strings. Third, set `approvals.origin` in `/etc/bas/broker.toml` to that HTTPS address and restart `bas-broker`.

```text
Approval browser
└── https://bas.example.com
    └── HTTPS reverse proxy on the broker host
        └── http://127.0.0.1:793
```

Keep the reverse proxy configuration and its certificate keys under administrator control. Restrict access with your firewall or private network, and keep the broker listener on loopback. Choose the hostname before enrolling a passkey, because passkeys are bound to that hostname.

### Use Tailscale Serve

Tailscale publishes the pages to your tailnet as the Tailscale Service `svc:bas`. First, define the service `svc:bas` on the Services page of the Tailscale admin console, with HTTPS on port 443. Second, run the command below on the broker machine. Third, approve the machine as a host of the service in the admin console when it asks.

```sh
sudo tailscale serve --service=svc:bas --https=443 127.0.0.1:793
tailscale serve status
```

```text
https://bas.TAILNET.ts.net (tailnet only) (svc:bas)
|-- / proxy http://127.0.0.1:793
```

The WebAuthn relying party ID is the hostname in `approvals.origin`. A passkey enrolled for that hostname cannot be used by a page on another hostname.

## 7. Enroll the first passkey

While no passkey is enrolled, the broker writes a one-time enrollment link to `/var/lib/bas/enroll-url`, which only root and the `bas` user can read.

```sh
sudo cat /var/lib/bas/enroll-url
```

Open the link on the device that will approve requests. For a YubiKey, open it in a browser on a computer with the key plugged in. For a phone passkey, open it on the phone. Name the passkey and choose Create passkey. The page says "Enrolled", and the broker deletes `enroll-url`. To add more passkeys later, run `bas passkey add` and approve with a passkey you already have.

## 8. Approve a first policy

The policy says which secrets the proxy may use, for which hosts and requests, and which SSH keys the ssh-agent signs with. Store each secret in Secrets Manager first, in the broker's project. For an SSH key, store the OpenSSH private key text, which must be an ed25519 or rsa key without a passphrase. Then copy the example policy, replace each `<secret-id>` with the ID of the secret, and send the policy for approval.

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

A shim is a small script that runs the real program with the broker's settings. The `gh` shim runs `gh` through the proxy, with the repository of the current directory, so the broker adds a GitHub App token for the same repository. The `ssh-keygen` shim sends git's signing requests to the broker's ssh-agent.

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

`10-bas.conf` tells `ssh` to ask the broker's ssh-agent for every host, so `ssh` and git over SSH use the keys in `[ssh.NAME]` entries with `use = ["auth"]`.

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

`/etc/ssh/ssh_config` must include `/etc/ssh/ssh_config.d/*.conf`, which it does by default on Debian and Ubuntu. The agent lists each key with the comment `bas:NAME`. Remove the old private key files from `~/.ssh`, and keep only the `.pub` files.

## 11. Sign git commits through the broker

git signs a commit by running `ssh-keygen -Y sign`, which uses `SSH_AUTH_SOCK` and ignores the ssh config. The system git setting below makes git run the `ssh-keygen` shim, which points `SSH_AUTH_SOCK` at the broker. Your own git settings name the public key to sign with.

```sh
sudo git config --system gpg.ssh.program /usr/local/lib/bas/shims/ssh-keygen
install -d -m 0700 ~/.ssh
SSH_AUTH_SOCK=/run/bas/ssh-agent.sock ssh-add -L | grep 'bas:git_signing' > ~/.ssh/git_signing.pub
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/git_signing.pub
git config --global commit.gpgsign true
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

The audit shows a `run` entry for the first command, a `deny` entry for the second, and a `sign` entry for the commit.

## Install on macOS

On macOS, a LaunchDaemon runs the broker as the role account `_bas`, and the files come from `contrib/macos/`. Steps 8, 10, and 11 above work the same way with `/var/run/bas/` in place of `/run/bas/`. Run the commands from an admin account, or from a root shell, while no agent runs.

```text
contrib/macos/                                  installed as
├── io.github.bjoernaagaard.bas.rundir.plist    /Library/LaunchDaemons/io.github.bjoernaagaard.bas.rundir.plist
├── io.github.bjoernaagaard.bas.broker.plist    /Library/LaunchDaemons/io.github.bjoernaagaard.bas.broker.plist
├── broker.toml.example                         /etc/bas/broker.toml
├── ../policy.toml.example                      ~/Library/Application Support/bas/policy.toml (your proposal)
├── shims/ssh-keygen                            /usr/local/lib/bas/shims/ssh-keygen
└── ssh_config.d/10-bas.conf                    /etc/ssh/ssh_config.d/10-bas.conf
```

First, make the account you work in a standard user. While it is an admin, its password is worth root, and an agent that runs as you can capture it with a fake prompt, or wait at a `sudo` prompt for a Touch ID or security key touch you meant for something else. Root can read the token. Keep a separate admin account, type its password only at the login window, and check that `id -Gn` no longer lists `admin` for your account. Also remove any `sudo` PAM module or `PATH` entry that your account can write, such as files under `/opt/homebrew`.

Then install the program and create `_bas`. The 450 to 499 range is for role accounts. Don't use `sysadminctl -addUser -roleAccount`, which on macOS 27 ignores `-UID` and gives `_bas` the next regular UID, such as 502. Create the account with `dscl` instead. The first command must print nothing, which means no account or group holds ID 450 yet.

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

Create the state, token, and log files. `read -s` hides what you paste. Don't put the token in a file of your own or on a command line.

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

The append-only flag lets the broker add lines and stops anyone but root from changing old ones. Only the broker reads the file, and `bas audit` asks the broker for it.

Install `broker.toml` and set the same keys as in step 4. Each Mac needs its own approval origin, such as `https://bas-mini.TAILNET.ts.net`, so a passkey never approves a request on the wrong broker. Then load both daemons.

```sh
sudo install -d -o root -g wheel -m 0755 /etc/bas
sudo install -o root -g wheel -m 0644 contrib/macos/broker.toml.example /etc/bas/broker.toml
sudo install -o root -g wheel -m 0644 contrib/macos/io.github.bjoernaagaard.bas.*.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.bjoernaagaard.bas.rundir.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.bjoernaagaard.bas.broker.plist
curl -s --unix-socket /var/run/bas/broker.sock http://localhost/v1/status
```

If the broker doesn't start, `/var/log/bas/broker.log` says why. The approval pages listen on `/var/run/bas/approve.sock`, which only `_bas` and root can open. Publish them with Tailscale Serve, which runs as root, as its own service per Mac.

```sh
sudo tailscale serve --service=svc:bas-mini --https=443 unix:/var/run/bas/approve.sock
sudo cat /var/db/bas/enroll-url
```

Enroll the first passkey from that link as in step 7. Install the `ssh-keygen` shim and `10-bas.conf` from `contrib/macos/` as in steps 9 to 11. There is no `gh` shim on macOS: Go programs there check certificates with the system verifier and ignore `SSL_CERT_FILE`, so they can't use the proxy.

To remove the broker, run `sudo launchctl bootout system/io.github.bjoernaagaard.bas.broker` and `sudo launchctl bootout system/io.github.bjoernaagaard.bas.rundir`, then delete the files above.

## Try the broker without installing it

A transient unit runs the broker as a throwaway user and leaves nothing behind. Put the program, a `broker.toml`, and a first `seed.toml` policy in `/dev/shm/basdev`, readable by every user, then run the commands below.

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

The transient broker uses the same socket and ports as the installed one, so stop `bas-broker` first if it runs.
