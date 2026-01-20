# CLAUDE.md

This file provides guidance to AI coding assistants when working with code in this repository.

## What This Project Is

An MCP (Model Context Protocol) server in Rust that connects to Erlang/BEAM nodes via the distribution protocol. It exposes 30+ tools for node introspection, debugging, tracing, and code evaluation — designed to be used by AI assistants.

## Build Commands

```bash
cargo build                    # Debug build
cargo test                     # Run all tests
cargo test test_name           # Run single test by name
cargo test module::            # Run all tests in a module
cargo fmt                      # Format code
cargo clippy --all-targets --all-features -D warnings  # Strict linting
```

Pre-commit verification (always run before committing):
```bash
cargo fmt && cargo clippy --all-targets --all-features -D warnings && cargo test
```

The local `.mcp.json` runs the debug binary directly (`target/debug/erl_dist_mcp`), so `cargo build` is needed before restarting the MCP server to pick up changes.

## Architecture

**Entry point**: `src/main.rs` — CLI parsing (clap), tokio runtime setup, starts MCP server over stdio.

**Six modules**, each with a clear responsibility:

- **`server.rs`** — `ErlDistMcpServer` implements `ServerHandler` from rmcp. Contains all `#[tool]` definitions and the embedded Elixir log handler source (`LOG_HANDLER_SOURCE`). This is by far the largest file.
- **`connection.rs`** — `ConnectionManager` handles concurrent Erlang node connections. Wraps `erl_dist` protocol (EPMD lookup, handshake, SSL). Each connection runs a background `connection_task` that multiplexes RPC request/response over the distribution channel.
- **`rpc.rs`** — Abstraction over erl_dist message passing for calling the `rex` process on remote nodes. Provides `rpc_call()` plus helper functions (`atom()`, `tuple()`, `list()`, `map()`, `binary_from_str()`) and extractors (`extract_ok_value()`, `extract_list()`, etc.) for working with EETF terms.
- **`formatter.rs`** — `TermFormatter` trait with four implementations: Erlang, Elixir, Gleam, LFE. Converts EETF terms into language-specific syntax strings. Selected at runtime via `FormatterMode`.
- **`trace.rs`** — `TraceManager` manages active trace sessions. Integrates with recon_trace (preferred) or falls back to dbg. Parses trace output files into structured `TraceEvent` variants.
- **`error.rs`** — `ConnectionError`, `RpcError`, `ToolError` using thiserror. Result type aliases: `ConnectionResult<T>`, `RpcResult<T>`, `ToolResult<T>`.

**Key patterns**:
- Tools are defined with `#[tool]` macros from rmcp, each taking a typed request struct (with schemars `JsonSchema`) and returning `Result<CallToolResult, McpError>`
- RPC calls go through `rpc::rpc_call()` which sends to the remote `rex` process and awaits response with a configurable timeout (default 5s)
- The `ensure_log_handler` pattern demonstrates deploying Elixir code to remote nodes via `Code.eval_string` RPC
- `ServerState` holds shared state behind `Arc`: connection manager, trace manager, formatter (behind `RwLock`), and the `allow_eval` flag

## Lint Configuration

Defined in `Cargo.toml`:
- `unsafe_code = "forbid"` — no unsafe allowed
- `unwrap_used = "warn"`, `expect_used = "warn"` — use proper error handling

## Key Dependencies

- `rmcp` — MCP server framework (tool macros, stdio transport)
- `erl_dist` / `eetf` — Erlang distribution protocol and term format
- `tokio` — async runtime
- `serde` / `schemars` — serialisation and JSON Schema for tool parameters
- `chrono` — timestamp formatting (log events use OTP microsecond timestamps)
