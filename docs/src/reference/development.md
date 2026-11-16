# Build and check bas

Run the commands under "Local checks" before you open a pull request, because CI runs the same checks. The repository builds one program, `bas`, from the four crates in the tree below.

```text
crates/
├── bas/          the CLI and the end-to-end runner in examples/e2e
├── bas-core/     profiles, references, the credential store, Secrets Manager calls
├── bas-tui/      the terminal UI
└── bas-broker/   the broker, Linux and macOS
contrib/policy.toml.example    policy example for both platforms
contrib/linux/    unit, settings, shims, and ssh config for the broker
contrib/macos/    LaunchDaemons, settings, shims, and ssh config for the broker
docs/             this site, built with mdBook
```

## Local checks

Run the commands below from the repository root. The last one is the offline end-to-end run.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo doc --locked --no-deps
cargo build --locked --release --bin bas --example e2e
./target/release/examples/e2e offline --bas "$(pwd)/target/release/bas" --artifacts "$(pwd)/target/e2e/local"
```

The offline run starts the built program and checks the behavior that needs no server, e.g., reference templates, refused launches, hidden input, and configuration checks. Each run needs a new artifact directory.

```text
target/e2e/local/
├── run.json         the manifest
├── cases.jsonl      one record per case
├── commands.jsonl   one record per command
├── output/          stdout and stderr of each command
└── summary.json     the same on every run
```

## Live checks

A live check needs a dedicated Secrets Manager project and a working OS credential store. Give the machine token to the runner through its environment only, and never as an argument or in chat.

```sh
BAS_E2E_ACCESS_TOKEN=... \
BAS_E2E_ORGANIZATION_ID=<organization-id> \
BAS_E2E_PROJECT_ID=<project-id> \
BAS_E2E_REGION=us \
./target/release/examples/e2e live-direct --bas "$(pwd)/target/release/bas" --artifacts "$(pwd)/target/e2e/live-direct"
```

Use `BAS_E2E_REGION=eu` for an account in the EU region. The run follows the steps below.

```text
e2e live-direct
  create a unique profile and a unique secret
  check login, find, run, update, exit codes, and logout
  remove the local profile
  keep the remote secret, because bas can't delete it
```

The report keeps the reference to the remote secret, so you can delete the secret by hand. If a requirement is missing, the runner exits with code 3 and records `not_run`. The artifacts never include live command output.

## CI and releases

Each workflow in `.github/workflows` runs on the events in the table below, and no workflow receives live vault credentials.

| Workflow | Runs on | What it does |
|---|---|---|
| `ci` (`ci.yml`) | Pull requests, pushes to `main`, on demand, and calls from `release` | Runs `cargo deny check advisories` and the local checks above. Pull requests build and check `bas` on Linux only, and the other runs build it on Linux, macOS, and Windows runners. Every run checks Rust 1.89 on Linux. |
| `release` (`release.yml`) | Every `v*` tag, and on demand | Runs `ci`, and on a tag publishes the archives as a GitHub release |
| `docs` (`docs.yml`) | Pushes to `main` and pull requests that change `docs/`, and on demand | Builds the site with mdBook, and publishes it to GitHub Pages except for a pull request |

Build the site locally with the commands below.

```sh
cd docs
mise exec -- mdbook build    # writes docs/book
```
