# Erlang Distribution MCP Server

A Model Context Protocol (MCP) server that connects to Erlang/BEAM nodes via the Erlang distribution protocol, providing AI assistants with tools for introspection, debugging, tracing, and code evaluation on remote Erlang systems.

[![CI](https://github.com/jimsynz/erl_dist_mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/jimsynz/erl_dist_mcp/actions/workflows/ci.yml)

## Features

- 🔌 **Dynamic Node Connections**: Connect to multiple Erlang nodes dynamically at runtime
- 🔍 **Process Introspection**: List, search, and inspect processes and their state
- 📊 **System Monitoring**: Memory usage, scheduler utilisation, ETS tables, and more
- 🐛 **Advanced Debugging**: Stack traces, message queues, GenServer state inspection
- 🔬 **Function Tracing**: Safe production tracing with recon or dbg
- 🎨 **Multi-Language Output**: Format output in Erlang, Elixir, Gleam, or LFE syntax
- 🚀 **Code Evaluation**: Execute arbitrary Erlang expressions (with safety guards)
- 🌳 **Supervision Trees**: Visualise OTP supervision hierarchies
- 📦 **Application Management**: List and inspect OTP applications

## Installation

### From Source (Recommended)

```bash
git clone https://github.com/jimsynz/erl_dist_mcp.git
cd erl_dist_mcp
cargo build --release
```

The binary will be at `target/release/erl_dist_mcp`.

### Using Cargo Install

```bash
cargo install erl_dist_mcp
```

### Pre-built Binaries

Download the latest release for your platform from the [releases page](https://github.com/jimsynz/erl_dist_mcp/releases).

Available targets:
- **Linux**: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`
- **macOS**: `x86_64-apple-darwin` (Intel), `aarch64-apple-darwin` (Apple Silicon)
- **Windows**: `x86_64-pc-windows-msvc`

Extract the archive and move the binary to a directory in your PATH:

```bash
# Linux/macOS
tar xzf erl_dist_mcp-*.tar.gz
sudo mv erl_dist_mcp /usr/local/bin/

# Windows (PowerShell)
Expand-Archive erl_dist_mcp-*.zip
Move-Item erl_dist_mcp.exe C:\Windows\System32\
```

### Platform-Specific Notes

**macOS**: On first run, you may see a security warning. Right-click the binary and select "Open" to bypass Gatekeeper, or run:

```bash
xattr -d com.apple.quarantine /usr/local/bin/erl_dist_mcp
```

**Windows**: You may need to add the binary location to your PATH environment variable.

**Linux (ARM)**: The `aarch64` build requires glibc 2.27 or later (Ubuntu 18.04+, Debian 10+).

### Verification

After installation, verify the binary works:

```bash
erl_dist_mcp --version
```

You should see output like:
```
erl_dist_mcp 0.1.0
```

Test the help output:
```bash
erl_dist_mcp --help
```

## Quick Start

### 1. Start an Erlang Node

First, start an Erlang node with distribution enabled:

```bash
# Erlang
erl -sname test -setcookie mycookie

# Elixir
iex --sname test --cookie mycookie

# Gleam (with Erlang runtime)
gleam run -- --name test --cookie mycookie
```

### 2. Configure Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "erlang": {
      "command": "/path/to/erl_dist_mcp",
      "args": ["--mode", "elixir", "--allow-eval"],
      "env": {}
    }
  }
}
```

**Configuration file locations:**
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

### 3. Use from Claude

Start Claude Desktop and try:

```
Connect to my local Elixir node at test@localhost with cookie mycookie
```

```
List all processes on the node sorted by memory usage
```

```
Show me the supervision tree for the main application
```

## CLI Reference

```
erl_dist_mcp [OPTIONS]

Options:
  --mode <MODE>           Output format mode [default: elixir]
                          Values: erlang, elixir, gleam, lfe

  --allow-eval            Enable code evaluation tools (rpc_call, eval_code)
                          WARNING: Only use with trusted nodes

  --log-level <LEVEL>     Set logging level [default: info]
                          Values: trace, debug, info, warn, error

  -h, --help              Print help information
  -V, --version           Print version information
```

### Output Modes

The `--mode` flag controls how Erlang terms are formatted:

- **erlang**: Standard Erlang syntax (e.g., `{ok, Value}`, `#{key => value}`)
- **elixir**: Idiomatic Elixir syntax (e.g., `{:ok, value}`, `%{key: value}`)
- **gleam**: Gleam-like syntax (e.g., `Ok(value)`, `#(tuple, elements)`)
- **lfe**: Lisp Flavoured Erlang (e.g., `#(ok value)`, `#m(key value)`)

You can change modes at runtime using the `set_mode` tool.

## Configuration for Different Editors

### Claude Desktop

See Quick Start section above.

### Cursor

Add to your Cursor MCP settings (`.cursor/mcp.json` or Cursor settings):

```json
{
  "mcpServers": {
    "erlang": {
      "command": "/path/to/erl_dist_mcp",
      "args": ["--mode", "elixir"],
      "env": {}
    }
  }
}
```

### Continue.dev

Add to `~/.continue/config.json`:

```json
{
  "mcpServers": [
    {
      "name": "erlang",
      "command": "/path/to/erl_dist_mcp",
      "args": ["--mode", "elixir"]
    }
  ]
}
```

### Cline (VS Code)

Add to VS Code settings under "Cline: MCP Servers":

```json
{
  "erl_dist_mcp": {
    "command": "/path/to/erl_dist_mcp",
    "args": ["--mode", "elixir"]
  }
}
```

## Available Tools

### Connection Management

| Tool | Description |
|------|-------------|
| `connect_node` | Connect to an Erlang node with authentication |
| `disconnect_node` | Disconnect from a node |
| `list_nodes` | List all connected nodes and their status |
| `set_mode` | Change output format (erlang/elixir/gleam/lfe) |

### Process Inspection

| Tool | Description |
|------|-------------|
| `list_processes` | List processes with memory, reductions, message queue length |
| `get_process_info` | Get comprehensive information about a specific process |
| `top_processes` | Find top processes by memory, reductions, or message queue |
| `find_process` | Search for processes by registered name or module |
| `get_message_queue` | Inspect a process's message queue (caution: expensive) |
| `get_process_stacktrace` | Get the current stack trace of a process |

### OTP & GenServer

| Tool | Description |
|------|-------------|
| `get_gen_server_state` | Get the internal state of an OTP process |
| `get_gen_server_status` | Get full status information from an OTP process |
| `get_supervision_tree` | Visualise supervision tree starting from a supervisor |
| `list_applications` | List all running OTP applications |
| `get_application_info` | Get detailed application metadata and configuration |

### System Information

| Tool | Description |
|------|-------------|
| `get_memory_info` | Memory breakdown (processes, system, binary, code, ETS, etc.) |
| `get_allocator_info` | Memory allocator statistics (requires recon) |
| `get_system_info` | System limits and counts (processes, ports, atoms, schedulers) |
| `get_scheduler_usage` | CPU scheduler utilisation per scheduler |

### ETS Tables

| Tool | Description |
|------|-------------|
| `list_ets_tables` | List all ETS tables with size and memory usage |
| `get_ets_table_info` | Get detailed information about an ETS table |
| `sample_ets_table` | Sample entries from an ETS table (caution: may be slow) |

### Tracing & Debugging

| Tool | Description |
|------|-------------|
| `start_trace` | Start function tracing (recon_trace or dbg fallback) |
| `stop_trace` | Stop a trace session |
| `get_trace_results` | Retrieve trace output from a session |
| `get_error_logger_events` | Get recent error log events (if available) |

### Module Information

| Tool | Description |
|------|-------------|
| `get_module_info` | Get module metadata (exports, attributes, compile info) |
| `list_module_functions` | List all exported functions from a module |

### Code Evaluation (Restricted)

| Tool | Description | Requires Flag |
|------|-------------|---------------|
| `rpc_call` | Make arbitrary RPC calls to any module | `--allow-eval` |
| `eval_code` | Evaluate Erlang expressions with bindings | `--allow-eval` |

## Security Considerations

### The `--allow-eval` Flag

**⚠️ IMPORTANT:** The `--allow-eval` flag enables powerful but dangerous tools that can execute arbitrary code on connected nodes:

- **rpc_call**: Can call any function on the remote node with any arguments
- **eval_code**: Can evaluate arbitrary Erlang expressions

**Only enable `--allow-eval` when:**
- You fully trust the AI assistant and its instructions
- You are connecting to development/test nodes, NOT production
- You understand the security implications
- You have reviewed what code will be executed

**Mitigation strategies:**
1. **Don't use `--allow-eval` in production environments**
2. **Use network firewalls** to restrict which nodes can be reached
3. **Use Erlang cookies** as a shared secret authentication mechanism
4. **Review generated code** before allowing execution
5. **Run on dedicated debug nodes** separate from production systems

### Erlang Distribution Security

The Erlang distribution protocol uses a shared secret (cookie) for authentication:

- **Store cookies securely**: Don't commit them to version control
- **Use strong cookies**: Long, random strings (not "mycookie")
- **Rotate cookies regularly** in production environments
- **Limit network access**: Use firewalls to restrict who can connect
- **Monitor connections**: Watch for unexpected connection attempts

### Code Evaluation Safety (`eval_code` tool)

The `eval_code` tool includes safety mechanisms:

- **Process-level sandbox**: Evaluation runs in a separate process with resource limits
- **Heap size limit**: Prevents memory exhaustion
- **Timeout**: Prevents infinite loops
- **Low priority**: Reduces impact on system performance
- **Function whitelist**: Only safe operations allowed (arithmetic, comparisons, list/map operations)
- **Blocks dangerous operations**: No file I/O, network, process spawning, or code loading

**Note:** These safety mechanisms are NOT a complete sandbox. Skilled attackers may find ways to bypass restrictions. Only use on nodes you control.

## Troubleshooting

### "Node unreachable" or "EPMD lookup failed"

**Problem:** Cannot connect to the Erlang node.

**Solutions:**
1. **Verify the node is running**: `epmd -names` should list your node
2. **Check node name format**: Should be `name@host` (e.g., `test@localhost`)
3. **Check EPMD port**: Ensure port 4369 is not blocked
4. **Check distribution port**: The node's distribution port must be accessible
5. **Verify hostname resolution**: `ping localhost` should work

### "Authentication failed for node"

**Problem:** Cookie mismatch between client and server.

**Solutions:**
1. **Check cookie on server**: In Erlang run `erlang:get_cookie()`, in Elixir run `Node.get_cookie()`
2. **Check cookie in connection command**: Must match exactly
3. **Check `.erlang.cookie` file**: Located in home directory on Unix systems
4. **Set cookie explicitly**: Use `-setcookie` flag when starting node

### "Connection lost" mid-operation

**Problem:** Network disruption or node crashed.

**Solutions:**
1. **Check node is still alive**: Use `epmd -names` or try `ping`
2. **Reconnect**: Use `connect_node` tool again
3. **Check for node restarts**: Application crashes may restart the node
4. **Review error logs**: Check both client and server logs

### "Tool requires --allow-eval flag"

**Problem:** Trying to use `rpc_call` or `eval_code` without permission.

**Solutions:**
1. **Restart server with flag**: Add `--allow-eval` to command arguments
2. **Update configuration**: Add flag to Claude Desktop config or Cursor settings
3. **Consider security**: Review security implications before enabling

### "Module not loaded: mcp_eval_helper"

**Problem:** The `eval_code` tool requires a helper module on the target node.

**Solutions:**
1. **Deploy the helper module**:
   ```bash
   cd /path/to/erl_dist_mcp
   # Copy to target node
   scp erlang/mcp_eval_helper.erl user@targethost:/tmp/

   # On target node (Erlang shell):
   c("/tmp/mcp_eval_helper").
   ```

2. **Verify module loaded**:
   ```erlang
   % Erlang
   code:which(mcp_eval_helper).

   # Elixir
   :code.which(:mcp_eval_helper)
   ```

### High memory usage or slow responses

**Problem:** Server consuming too many resources.

**Solutions:**
1. **Reduce trace limits**: Lower max_traces when using `start_trace`
2. **Avoid large message queues**: Don't use `get_message_queue` on processes with >1000 messages
3. **Limit ETS sampling**: Use small limits with `sample_ets_table`
4. **Check process limits**: Ensure node has sufficient resources
5. **Enable streaming**: Some tools support streaming large result sets

### "Unexpected response format" errors

**Problem:** Tool received data in unexpected format from Erlang node.

**Solutions:**
1. **Check Erlang/OTP version**: Some features require specific versions
2. **Verify node type**: Ensure you're connected to an Erlang/BEAM node
3. **Report issue**: This may be a bug - please file an issue with details

## Examples

### Connecting and Basic Inspection

```
Connect to test@localhost with cookie mycookie

List all processes sorted by memory

Show the top 5 processes by reductions
```

### Debugging a Specific Process

```
Find processes with registered name "my_server"

Get the full process info for <0.123.0>

Show me the stack trace for that process

Get the GenServer state for <0.123.0>
```

### Monitoring System Health

```
Show me the memory breakdown for the node

Get the scheduler usage (CPU utilisation)

List all ETS tables sorted by memory usage

Show system info - how close are we to process limits?
```

### Investigating an Application

```
List all running applications

Get detailed info for the "myapp" application

Show the supervision tree starting from myapp_sup
```

### Tracing Function Calls

```
Start tracing calls to my_module:my_function/2 with max 100 traces

Get the trace results

Stop the trace
```

### Using Different Output Modes

```
Set mode to erlang

Show me the process info for <0.123.0>

Set mode to gleam

Show me that again
```

## Development

### Building

```bash
cargo build
```

### Running Tests

```bash
cargo test
```

### Linting

```bash
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

### Running Locally

```bash
cargo run -- --mode elixir --allow-eval --log-level debug
```

## Architecture

The server consists of several key components:

- **Connection Manager**: Manages multiple Erlang node connections
- **RPC Layer**: Handles remote procedure calls via the rex process
- **Formatters**: Convert Erlang terms to language-specific syntax
- **Trace Manager**: Manages function tracing sessions
- **MCP Server**: Exposes tools via the Model Context Protocol

Key design decisions:
- **Runtime-agnostic erl_dist**: Uses futures_io traits, works with tokio runtime via adapter
- **Background connection tasks**: Each node connection runs in its own tokio task
- **Trait-based formatting**: Pluggable formatters for different BEAM languages
- **Comprehensive error handling**: All errors include contextual information

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes with tests
4. Ensure all tests pass (`cargo test`)
5. Ensure clippy is happy (`cargo clippy --all-targets --all-features -- -D warnings`)
6. Format your code (`cargo fmt`)
7. Commit your changes (`git commit -m 'feat: add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

## License

This project is licensed under the Apache License, Version 2.0 — see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [erl_dist](https://github.com/beamform/erl_dist) - Erlang distribution protocol client
- [rmcp](https://github.com/modelcontextprotocol/rmcp) - Model Context Protocol server framework
- [recon](https://ferd.github.io/recon/) - Erlang/OTP production debugging tools
- [Model Context Protocol](https://modelcontextprotocol.io/) - Protocol specification

