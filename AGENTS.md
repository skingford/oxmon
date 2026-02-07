# Repository Guidelines

## Project Structure & Module Organization
- `crates/` contains the Rust workspace crates (agent, server, storage, alert, notify, common, collector).
- `config/` holds example and local TOML configs (`agent.example.toml`, `server.example.toml`).
- `proto/` contains gRPC protobuf definitions shared by agent and server.
- `openspec/` tracks OpenSpec change artifacts and archived specs.
- `target/` is build output (generated).

## Build, Test, and Development Commands
- `cargo build --release`: build both `oxmon-agent` and `oxmon-server` binaries.
- `cargo test --workspace`: run all workspace tests.
- `cargo clippy --workspace -- -D warnings`: lint; CI treats warnings as errors.
- `make release`: cross-compile and package all supported targets (see `Makefile`).

## Coding Style & Naming Conventions
- Rust 2021 edition workspace; follow standard Rust formatting (`cargo fmt`).
- Naming: `snake_case` for functions/modules, `PascalCase` for types, `SCREAMING_SNAKE_CASE` for consts.
- Keep modules small and focused; prefer adding functionality within the relevant crate under `crates/`.

## Testing Guidelines
- Unit tests live alongside crates, typically in `crates/*/src/tests.rs`.
- Use `cargo test --workspace` before opening a PR.
- Add tests for new alert rules, storage behavior, and notification plugins when you change them.

## Commit & Pull Request Guidelines
- Commit messages follow a conventional style seen in history: `feat: ...`, `fix: ...`, `chore: ...`.
- PRs should include a clear summary, testing notes (commands run), and config/API changes when applicable.
- If you add or modify REST endpoints, update OpenAPI outputs served by the server and note them in the PR.

## Security & Configuration Tips
- Keep secrets out of `config/*.toml`; use environment-specific overrides where possible.
- Validate new notification plugins for safe URL handling and TLS settings (server uses Rustls).
