//! Error types for the Erlang Distribution MCP Server.
//!
//! This module defines the core error types used throughout the crate:
//! - `ConnectionError` - errors related to node connections
//! - `RpcError` - errors from remote procedure calls
//! - `ToolError` - errors from MCP tool execution

use thiserror::Error;

/// Errors that can occur when connecting to or communicating with Erlang nodes.
#[derive(Debug, Error)]
pub enum ConnectionError {
    /// The specified node could not be reached.
    #[error("node '{node}' is unreachable: {reason}")]
    NodeUnreachable { node: String, reason: String },

    /// Authentication failed (wrong cookie).
    #[error("authentication failed for node '{node}': invalid cookie")]
    AuthenticationFailed { node: String },

    /// A connection to this node already exists.
    #[error("already connected to node '{node}'")]
    AlreadyConnected { node: String },

    /// The specified node is not connected.
    #[error("not connected to node '{node}'")]
    NotConnected { node: String },

    /// The handshake with the node failed.
    #[error("handshake failed with node '{node}': {reason}")]
    HandshakeFailed { node: String, reason: String },

    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The connection was lost unexpectedly.
    #[error("connection lost to node '{node}': {reason}")]
    ConnectionLost { node: String, reason: String },
}

/// Errors that can occur during remote procedure calls.
#[derive(Debug, Error)]
pub enum RpcError {
    /// The RPC call timed out.
    #[error("RPC to {node}:{module}:{function} timed out after {timeout_ms}ms")]
    Timeout {
        node: String,
        module: String,
        function: String,
        timeout_ms: u64,
    },

    /// The remote node returned a badrpc error.
    #[error("bad RPC to {node}:{module}:{function}: {reason}")]
    BadRpc {
        node: String,
        module: String,
        function: String,
        reason: String,
    },

    /// The specified node is not connected.
    #[error("cannot call {module}:{function} - not connected to node '{node}'")]
    NodeNotConnected {
        node: String,
        module: String,
        function: String,
    },

    /// Failed to encode the RPC arguments.
    #[error("failed to encode arguments for {module}:{function}: {reason}")]
    EncodeError {
        module: String,
        function: String,
        reason: String,
    },

    /// Failed to decode the RPC response.
    #[error("failed to decode response from {module}:{function}: {reason}")]
    DecodeError {
        module: String,
        function: String,
        reason: String,
    },

    /// The underlying connection encountered an error.
    #[error("connection error during RPC: {0}")]
    Connection(#[from] ConnectionError),
}

/// Errors that can occur during MCP tool execution.
#[derive(Debug, Error)]
pub enum ToolError {
    /// Invalid arguments were provided to the tool.
    #[error("invalid arguments for tool '{tool}': {reason}")]
    InvalidArguments { tool: String, reason: String },

    /// A required argument was missing.
    #[error("missing required argument '{argument}' for tool '{tool}'")]
    MissingArgument { tool: String, argument: String },

    /// The tool requires the --allow-eval flag.
    #[error("tool '{tool}' requires --allow-eval flag to be enabled")]
    EvalNotAllowed { tool: String },

    /// An RPC error occurred during tool execution.
    #[error("RPC error in tool '{tool}': {source}")]
    Rpc {
        tool: String,
        #[source]
        source: RpcError,
    },

    /// A connection error occurred during tool execution.
    #[error("connection error in tool '{tool}': {source}")]
    Connection {
        tool: String,
        #[source]
        source: ConnectionError,
    },

    /// An internal error occurred.
    #[error("internal error in tool '{tool}': {reason}")]
    Internal { tool: String, reason: String },
}

/// Result type alias for connection operations.
pub type ConnectionResult<T> = Result<T, ConnectionError>;

/// Result type alias for RPC operations.
pub type RpcResult<T> = Result<T, RpcError>;

/// Result type alias for tool operations.
pub type ToolResult<T> = Result<T, ToolError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_error_display() {
        let err = ConnectionError::NodeUnreachable {
            node: "foo@localhost".to_string(),
            reason: "connection refused".to_string(),
        };
        assert!(err.to_string().contains("foo@localhost"));
        assert!(err.to_string().contains("unreachable"));
    }

    #[test]
    fn rpc_error_display() {
        let err = RpcError::Timeout {
            node: "bar@localhost".to_string(),
            module: "erlang".to_string(),
            function: "node".to_string(),
            timeout_ms: 5000,
        };
        assert!(err.to_string().contains("bar@localhost"));
        assert!(err.to_string().contains("timed out"));
    }

    #[test]
    fn tool_error_display() {
        let err = ToolError::InvalidArguments {
            tool: "connect_node".to_string(),
            reason: "node name cannot be empty".to_string(),
        };
        assert!(err.to_string().contains("connect_node"));
        assert!(err.to_string().contains("invalid arguments"));
    }

    #[test]
    fn result_type_aliases_compile() {
        fn _connection_fn() -> ConnectionResult<()> {
            Ok(())
        }

        fn _rpc_fn() -> RpcResult<String> {
            Ok(String::new())
        }

        fn _tool_fn() -> ToolResult<Vec<u8>> {
            Ok(vec![])
        }
    }
}
