# Install the broker

Run `bas broker install` as root on Linux, and then do steps 2 to 5 by hand, from a console or SSH session where no agent is running. On a Mac, follow [Install on macOS](#install-on-macos) instead.

```text
you                                     bas broker install
  1. run it with sudo                     copies bas to /usr/local/bin/bas
                                          creates the system user bas
                                          asks for the machine token and seals it
                                          writes the systemd unit and /etc/bas/broker.toml
                                          starts bas-broker.service
                                          installs the gh and ssh-keygen shims and the ssh config
                                          sets the system Git signing program
  2. publish the approval pages
  3. enroll the first passkey
  4. approve a first policy
  5. put the shims on PATH and choose a signing key
```

## Before you start

Have each item in the table ready before step 1.

| You need | Details |
|---|---|
| A Linux machine | It needs systemd with `systemd-creds`, which Ubuntu 22.04 and Debian 12 and later have. |
| `bas` v0.9.0 or later | Install it as [Install bas](../getting-started/install.md) describes. |
| A Secrets Manager machine account for the broker, and an access token for it | Give the account read access to the project that holds the secrets the policy names. Give it write access to the project where `bas add` should create new secrets. |
| Your organization ID, and the project ID for `bas add` | The Secrets Manager web app shows both. |
| An HTTPS address for the approval pages | Such as `https://bas.example.com`. For Tailscale Serve, use `https://bas.TAILNET.ts.net`, where `TAILNET` is the name of your tailnet. Choose it now, because passkeys are bound to its hostname. |
| A passkey device | A YubiKey, or a phone or password manager that holds passkeys |

## 1. Run the install

Run the command below with your own IDs and address, and paste the machine token when it asks. `sudo` doesn't search your own `PATH`, so the command gives it the full path of `bas`.

```sh
sudo "$(command -v bas)" broker install \
  --organization <organization-id> --project <project-id> \
  --origin https://bas.example.com
```

With mise shims on your `PATH`, write `"$(mise which bas)"` in place of `"$(command -v bas)"`.

The command prints its plan, and then it runs each step that the plan marks with `change`.

```text
change   program          /usr/local/bin/bas: create it
change   system user      bas: create it with useradd, with no login shell
change   machine token    /etc/credstore.encrypted/bas-bws.cred: ask for the token and seal it with systemd-creds
change   systemd unit     /etc/systemd/system/bas-broker.service: create it
change   settings         /etc/bas/broker.toml: write it from the options
change   service          bas-broker.service: enable it, and start it again with the changes above
change   gh shim          /usr/local/lib/bas/shims/gh: create it
change   ssh-keygen shim  /usr/local/lib/bas/shims/ssh-keygen: create it
change   ssh config       /etc/ssh/ssh_config.d/10-bas.conf: create it
change   git signing      gpg.ssh.program in the system Git settings: set it to /usr/local/lib/bas/shims/ssh-keygen
```

| Option | What it sets |
|---|---|
| `--dry-run` | Prints the plan and changes nothing. It needs no root. |
| `--organization <ID>` | `organization` in `[profile]` of `broker.toml` |
| `--project <ID>` | `project` in `[profile]`, where `bas add` creates new secrets |
| `--origin <URL>` | `origin` in `[approvals]`, the HTTPS address of the approval pages |
| `--region eu` | The endpoints for the EU region. `--server-url`, or `--api-url` with `--identity-url`, name a server of your own. |
| `--profile <NAME>` | The `PROFILE` in `bas://PROFILE/SECRET-ID`, which is `home` by default |
| `--allow-uid <UID>` | A user who may use the broker. The default is the user who ran `sudo`. |

The token goes from the hidden prompt of `systemd-ask-password` straight into `systemd-creds`, which encrypts it with a key that only root can read. It is never an argument, and `bas` never holds it.

```text
/etc/credstore.encrypted/bas-bws.cred    root, 0600, encrypted
└── LoadCredentialEncrypted=bws:...      in bas-broker.service
    └── $CREDENTIALS_DIRECTORY/bws       decrypted, for the broker's service only
```

A second run changes nothing, because each step first reads what the machine holds.

```text
on(bas broker install)
  for each step
    if the machine already matches
      print ready
    else
      print change, and run the step
  if /etc/bas/broker.toml exists
    keep it                      # edit it with sudoedit, then restart bas-broker
  if the sealed token exists
    keep it                      # remove the file and run the install again to seal another
```

After you update `bas`, run the same command again without options. It replaces `/usr/local/bin/bas` and the shims with the new release and restarts the service.

If the service doesn't start, `journalctl -u bas-broker -e` shows why, for example a token that Secrets Manager refused. Until you approve a first policy, the active policy is empty and allows nothing.

## 2. Publish the approval pages

Publish the approval pages, which listen on `127.0.0.1:793`, through an HTTPS reverse proxy. Choose the hostname before you enroll a passkey, because passkeys are bound to that hostname. Tailscale is optional, and you need no Tailscale account when you use another reverse proxy.

The WebAuthn relying party ID is the hostname in `approvals.origin`. A passkey enrolled for that hostname can't be used by a page on another hostname.

### Use an existing HTTPS reverse proxy

Forward one HTTPS hostname to `http://127.0.0.1:793` on the broker host.

1. Choose a hostname with a TLS certificate that your approval browser trusts.
2. Configure your reverse proxy to forward requests for that hostname to `http://127.0.0.1:793` on the broker host, and keep paths and query strings as they are.
3. Check that `approvals.origin` in `/etc/bas/broker.toml` is that HTTPS address. If you change it, restart `bas-broker`.

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

## 3. Enroll the first passkey

Open the one-time enrollment link on the device that will approve requests. While no passkey is enrolled, the broker writes the link to `/var/lib/bas/enroll-url`, which only root and the `bas` user can read.

```sh
sudo cat /var/lib/bas/enroll-url
```

| Passkey device | Where you open the link |
|---|---|
| YubiKey | In a browser on a computer with the key plugged in |
| Phone passkey | On the phone |

Name the passkey and choose Create passkey. The page says "Enrolled", and the broker deletes `enroll-url`. To add more passkeys later, run `bas passkey add` and approve with a passkey you already have.

## 4. Approve a first policy

Store your secrets in Secrets Manager, write a policy that names them, and approve the policy with your passkey. The policy says which secrets the proxy may use, for which hosts and requests, and which SSH keys the ssh-agent signs with.

1. Store each secret in Secrets Manager, in the broker's project. For an SSH key, store the OpenSSH private key text, which must be an ed25519 or rsa key without a passphrase.
2. Run `bas policy edit`, which opens the active policy in your editor.
3. Add your entries, with the [example policy](https://github.com/bjoernaagaard/bas/blob/main/contrib/policy.toml.example) as the model, and replace each `<secret-id>` with the ID of the secret.

```sh
bas policy edit
```

The editor is the one in `$VISUAL` or `$EDITOR`. After you save and quit, it prints the diff and the approval URL, and it waits. Open the URL, check the diff, and approve with your passkey.

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

## 5. Put the shims on PATH and choose a signing key

Put `/usr/local/lib/bas/shims` first in your `PATH`, so that `gh` and Git's `ssh-keygen` go through the broker. With mise, add the directory in a mise config file, such as `~/.config/mise/conf.d/bas.toml`.

```toml
[env]
_.path = ["/usr/local/lib/bas/shims"]
```

Without mise, put the directory first in `PATH` in your shell profile. Then check that `command -v gh` prints `/usr/local/lib/bas/shims/gh`.

The `gh` shim runs `gh` through the proxy with the repository of the current directory, so the broker adds a GitHub App token for the same repository. The `ssh-keygen` shim sends git's signing requests to the broker's ssh-agent, as the end of this step shows.

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

The install pointed `ssh` at the broker's ssh-agent for every host, so `ssh` and git over SSH use the keys in `[ssh.NAME]` entries with `use = ["auth"]`. Check it with the commands below, and then remove the old private key files from `~/.ssh` and keep only the `.pub` files.

```sh
SSH_AUTH_SOCK=/run/bas/ssh-agent.sock ssh-add -L
ssh -T git@github.com
```

```text
ssh-ed25519 AAAA... bas:git_signing
ssh-ed25519 AAAA... bas:github
Hi USER! You've successfully authenticated, but GitHub does not provide shell access.
```

`/etc/ssh/ssh_config` must include `/etc/ssh/ssh_config.d/*.conf`, which it does by default on Debian and Ubuntu.

The install also made Git sign through the `ssh-keygen` shim. Name the public key to sign with in your own Git settings.

```sh
install -d -m 0700 ~/.ssh
SSH_AUTH_SOCK=/run/bas/ssh-agent.sock ssh-add -L | grep 'bas:git_signing' > ~/.ssh/git_signing.pub
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/git_signing.pub
git config --global commit.gpgsign true
```

```text
git commit
└── gpg.ssh.program = /usr/local/lib/bas/shims/ssh-keygen
    └── SSH_AUTH_SOCK=/run/bas/ssh-agent.sock /usr/bin/ssh-keygen -Y sign
        └── the broker's ssh-agent signs with the key in ~/.ssh/git_signing.pub
```

A key with `use = ["sign-git"]` signs only SSH signatures in the `git` namespace, which is what `git commit -S` and `git tag -s` ask for. It can't sign an SSH login.

## Check the install

Run `bas doctor --broker` in a Git repository, and it exits 0 when the broker answers, its machine account sees every reference of the policy, and Git signs a commit through the broker.

```sh
bas doctor --broker
```

Then run the commands below in a scratch Git repository. The first two need a `JINA_API_KEY` entry in the policy, so use the name of any `[secret.NAME]` entry you have.

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

Run the commands in this section from an admin account, or from a root shell, while no agent runs. On macOS, a LaunchDaemon runs the broker as the role account `_bas`, and the files come from `contrib/macos/`. `bas broker install` supports Linux only, so on macOS you run each command yourself. Steps 4 and 5 above work the same way with `/var/run/bas/` in place of `/run/bas/`.

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

Install `broker.toml`, set the keys that its comments describe, and load both daemons. Give each Mac its own approval origin, such as `https://bas-mini.TAILNET.ts.net`, so a passkey never approves a request on the wrong broker.

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
| Enroll the first passkey | Open the link as in step 3. |
| Install the `gh` and `ssh-keygen` shims and `10-bas.conf` | Run the commands below from the extracted archive. The macOS `gh` shim reads the broker's certificate bundle from `/var/run/bas/ca-bundle.pem`. |
| Approve a policy, and set up `PATH` and signing | Follow steps 4 and 5. |

```sh
sudo install -d -o root -g wheel -m 0755 /usr/local/lib/bas/shims
sudo install -o root -g wheel -m 0755 contrib/macos/shims/gh contrib/macos/shims/ssh-keygen /usr/local/lib/bas/shims/
sudo install -o root -g wheel -m 0644 contrib/macos/ssh_config.d/10-bas.conf /etc/ssh/ssh_config.d/
sudo git config --system gpg.ssh.program /usr/local/lib/bas/shims/ssh-keygen
```

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
