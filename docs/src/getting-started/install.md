# Install bas

Download the release archive for your platform, extract it, and put `bas` on your `PATH`, or build `bas` from source with Rust 1.89 or newer.

## Install from a release

Get the archive for your platform from the [releases page](https://github.com/bjoernaagaard/bas/releases), or let mise install it with `mise use -g github:bjoernaagaard/bas`.

| Platform | Archive | What it holds besides the README |
|---|---|---|
| Linux on x86_64 | `bas-Linux-X64.tar.gz` | `bas`, `contrib/linux/` with the service unit, example settings, and shims, and `contrib/policy.toml.example` |
| macOS on ARM64 | `bas-macOS-ARM64.tar.gz` | `bas`, `contrib/macos/` with the LaunchDaemons, and `contrib/policy.toml.example` |
| Windows on x86_64 | `bas-Windows-X64.tar.gz` | `bas.exe` |

Every archive from v0.9.1 on has a build provenance record, which says that GitHub Actions built the archive from this repository at the release tag. mise checks the record on every install, and you can check a downloaded archive yourself with the GitHub CLI.

```sh
gh attestation verify bas-Linux-X64.tar.gz -R bjoernaagaard/bas
```

```text
on(mise use -g github:bjoernaagaard/bas)
  download the archive for your platform
  if its digest or its build provenance record doesn't match
    stop, and install nothing
  put bas on PATH
```

Check that no other program already uses the name `bas` before you copy `bas` onto your `PATH`. Run `command -v bas` on Linux and macOS, or `Get-Command bas` in PowerShell.

```text
on(install bas)
  if command -v bas finds another program
    keep bas in its own directory and call it by its full path
  else
    copy bas onto PATH
```

On Linux, the steps look like the commands below.

```sh
tar -xzf bas-Linux-X64.tar.gz
command -v bas || echo "the name bas is free"
install -d -m 0755 ~/.local/bin
install -m 0755 bas ~/.local/bin/bas
export PATH="$HOME/.local/bin:$PATH"
bas --version
```

Tailscale is optional on every platform.

## Build from source

Install Rust 1.89 or newer and the native build tools for your platform, and then build with Cargo.

```sh
git clone https://github.com/bjoernaagaard/bas
cd bas
cargo build --locked --release
./target/release/bas --version
```

| You need | Details |
|---|---|
| Rust 1.89 or newer | Grants use the file locks in the standard library |
| The native build tools for your platform | Cargo needs them to compile and link `bas` |
| On Linux, the OpenSSL development files and `pkg-config` | On Debian and Ubuntu, install the `libssl-dev` and `pkg-config` packages |
| Access to crates.io and to the `bitwarden/agent-access` repository on GitHub | The Agent Access crates come from a pinned Git revision, which the first build downloads |

The build makes one program. On Windows, the program is `target\release\bas.exe`.

```text
target/release/
└── bas      # one program: the CLI, the terminal UI, and on Linux and macOS the broker
```

## Next step

Sign in with a machine account access token, as [Sign in with an access token](first-run.md) shows.
