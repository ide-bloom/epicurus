# Contributing to Epicurus

Thanks for helping. Bug reports, decoy catalog entries, false-positive reports and code are all welcome.

## Development setup

- Windows 11 or Windows Server 2025
- Rust stable with the MSVC toolchain (`rustup default stable-x86_64-pc-windows-msvc`)
- Visual Studio Build Tools with the C++ workload and a Windows SDK (for the resource compiler and C dependencies)

```powershell
cargo build
cargo test --workspace                               # unit tests, no admin rights needed
cargo test -p epicurus-cli --features integration -- --test-threads=1   # end-to-end, elevated terminal
cargo clippy --workspace --all-targets --features epicurus-cli/integration -- -D warnings
cargo fmt --all
```

The integration tests run a real ETW engine and the SACL/4663 fallback against temporary folders. The audit test switches the machine-wide "File System" audit subcategory on and restores the previous value afterwards. A third test (`install_simulate_uninstall_leaves_nothing_behind`) installs the real service into your real profile, so it only runs when `EPICURUS_TEST_INSTALL=1` is set; CI sets it on its throwaway runners. Do not set it on a machine you care about.

To try the engine without installing the service, from an elevated terminal:

```powershell
cargo run -- --pipe epicurus-dev --data-dir .\dev-data service --foreground --session-name Epicurus-Dev --profile-root .\dev-home
cargo run -- --pipe epicurus-dev plant
cargo run -- --pipe epicurus-dev simulate --keep
```

## Code standards

- No `unwrap`/`expect` outside tests unless the case is truly infallible, with a comment saying why (enforced by clippy).
- Typed errors (`thiserror`) in libraries; `anyhow` only at the edges.
- Every `unsafe` block is minimal and has a `// SAFETY:` comment (enforced by `clippy::undocumented_unsafe_blocks`).
- Doc comments on public items. Comments explain *why*, not *what*.
- New behavior comes with tests. Safety logic (anything that decides where files go or which files may be deleted) lives in `epicurus-core` and must be unit-tested.

## Decoy catalog contributions

Read [docs/decoy-catalog.md](docs/decoy-catalog.md). Never commit token-shaped literals: use generators, and assemble provider prefixes from fragments in code and tests. In the PR, explain which stealer families or public reports target the location you are adding.

## Pull requests

- Keep PRs focused; describe the problem and how you tested it.
- Update `CHANGELOG.md` under *Unreleased* and any affected documentation. The README must describe only what exists.
- CI must pass: fmt, clippy, tests, cargo-deny, release builds.

By contributing you agree that your contributions are dual-licensed under MIT and Apache-2.0, as described in the README.
