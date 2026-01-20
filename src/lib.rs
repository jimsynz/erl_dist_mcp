//! Erlang Distribution MCP Server
//!
//! A Rust MCP server that connects to Erlang/BEAM nodes via the distribution
//! protocol, exposing tools for introspection, debugging, tracing, and code
//! evaluation.

pub mod connection;
pub mod error;
pub mod formatter;
pub mod rpc;
pub mod server;
pub mod trace;

pub use connection::{ConnectionManager, ConnectionState, NodeConnection, NodeStatus};
pub use error::{ConnectionError, ConnectionResult, RpcError, RpcResult, ToolError, ToolResult};
pub use formatter::{TermFormatter, get_formatter};
pub use rpc::{
    DEFAULT_RPC_TIMEOUT_MS, FromTerm, ToTerm, atom, binary, binary_from_str, extract_atom,
    extract_binary, extract_error_reason, extract_list, extract_map, extract_ok_value,
    extract_tuple, is_atom, is_error_tuple, is_nil, is_ok_tuple, list, map, nil, rpc_call, tuple,
};
pub use server::{ErlDistMcpServer, FormatterMode, ServerState};
pub use trace::{TraceManager, TraceParams, TraceSession};
