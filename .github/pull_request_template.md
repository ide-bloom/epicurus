## What and why

<!-- Describe the change and the problem it solves. -->

## How it was tested

<!-- Unit tests, integration test (elevated), manual steps. -->

## Checklist

- [ ] `cargo fmt`, `cargo clippy -- -D warnings` and `cargo test --workspace` pass
- [ ] Safety-relevant logic (where files go, what may be deleted, what may be contained) is unit-tested
- [ ] No token-shaped literals were added (generators and prefix fragments only)
- [ ] `CHANGELOG.md` (Unreleased) and affected docs are updated; the README describes only what exists
