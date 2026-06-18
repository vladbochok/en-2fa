# Repository Guidelines

## Project Structure & Module Organization

This repository contains a Rust CLI for approving zkSync batch execution hashes from an External Node database.

- `src/main.rs` wires CLI parsing, Ethereum RPC access, database setup, and the main polling/single-batch flow.
- `src/db.rs` contains the `BatchDb` abstraction and Postgres queries.
- `src/merkle.rs` builds and updates priority-operation Merkle data, including L1 backfill logic.
- `src/utils.rs` holds calldata and proof extraction helpers.
- `.env.example` documents required runtime configuration. Keep real `.env` values local.
- `Dockerfile`, `Cargo.toml`, and `Cargo.lock` define packaging and Rust dependencies.

## Build, Test, and Development Commands

- `cargo fmt` formats Rust code using the standard formatter.
- `cargo check` performs a fast compile/type check without building final artifacts.
- `cargo test` runs inline unit tests in `src/main.rs` and `src/merkle.rs`.
- `cargo run` starts the main polling mode using `.env` or CLI-provided values.
- `cargo run -- --chain-address <addr> --run-one-batch <batch> --dry-run 1` runs one batch without sending a transaction.
- `cargo build --release` creates an optimized binary under `target/release/`.

## Coding Style & Naming Conventions

Use idiomatic Rust 2024. Run `cargo fmt` before committing. Prefer clear module-level responsibilities and keep database access behind the `BatchDb` trait when possible. Use `snake_case` for functions, variables, and modules; `PascalCase` for structs, traits, and enums; and `SCREAMING_SNAKE_CASE` for constants. Use `anyhow::Context` on fallible RPC, DB, parsing, and decoding operations so failures remain actionable.

## Testing Guidelines

Place focused unit tests near the code they exercise in `#[cfg(test)] mod tests`. Name tests after the expected behavior, for example `parses_execute_payload_with_priority_ops`. Prefer deterministic tests for Merkle and encoding logic. For database or Ethereum RPC behavior, use `--dry-run 1` during manual validation and document the environment used.

## Commit & Pull Request Guidelines

Existing history uses short imperative summaries such as `Add timeout` and `Fixes after e2e tests`. New commits should stay concise and describe the behavior changed. Pull requests should include the purpose, validation performed (`cargo fmt`, `cargo test`, dry-run command), any required environment variables, and operational risk. Link related issues when available and include logs or screenshots only when they clarify runtime behavior.

## Security & Configuration Tips

Never commit private keys, RPC credentials, database URLs with secrets, or production `.env` files. Use `.env.example` for placeholders only. Default to `DRY_RUN=1` when validating new chain addresses, validator addresses, or batch numbers.
