//! Connection manager for Erlang node connections.
//!
//! This module provides the `ConnectionManager` for tracking multiple Erlang node
//! connections, and `NodeConnection` for managing individual connections.

use crate::error::{ConnectionError, ConnectionResult};
use eetf::Term;
use erl_dist::epmd::EpmdClient;
use erl_dist::handshake::{ClientSideHandshake, HandshakeStatus};
use erl_dist::message::{self, Message, Receiver, Sender};
use erl_dist::node::{Creation, LocalNode, NodeName, PeerNode};
use futures_io::{AsyncRead, AsyncWrite};
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::task::JoinHandle;

/// A wrapper around TcpStream that implements Clone and futures_io traits.
/// Clone is implemented by wrapping in Arc, allowing shared access.
#[derive(Clone)]
struct ClonableStream {
    inner: Arc<Mutex<TcpStream>>,
}

impl ClonableStream {
    fn new(stream: TcpStream) -> Self {
        Self {
            inner: Arc::new(Mutex::new(stream)),
        }
    }
}

impl AsyncRead for ClonableStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut guard = match self.inner.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };
        let stream = &mut *guard;
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(stream).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for ClonableStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut guard = match self.inner.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };
        let stream = &mut *guard;
        Pin::new(stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = match self.inner.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };
        let stream = &mut *guard;
        Pin::new(stream).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = match self.inner.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };
        let stream = &mut *guard;
        Pin::new(stream).poll_shutdown(cx)
    }
}

/// Request sent to the background connection task for RPC calls.
#[derive(Debug)]
pub struct RpcRequest {
    /// The message to send.
    pub message: Message,
    /// Channel to send the response back.
    pub response_tx: mpsc::Sender<RpcResponse>,
}

/// Response from an RPC call.
#[derive(Debug)]
pub enum RpcResponse {
    /// Successfully received a response term.
    Success(Term),
    /// The RPC failed with an error.
    Error(ConnectionError),
}

/// State of a node connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection is being established.
    Connecting,
    /// Connection is active and ready for use.
    Connected,
    /// Connection has been disconnected.
    Disconnected,
    /// Connection failed.
    Failed,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::Connecting => write!(f, "connecting"),
            ConnectionState::Connected => write!(f, "connected"),
            ConnectionState::Disconnected => write!(f, "disconnected"),
            ConnectionState::Failed => write!(f, "failed"),
        }
    }
}

/// Status information about a connected node.
#[derive(Debug, Clone)]
pub struct NodeStatus {
    /// The node name.
    pub name: String,
    /// Current connection state.
    pub state: ConnectionState,
    /// When the connection was established (if connected).
    pub connected_at: Option<Instant>,
}

/// A connection to a single Erlang node.
pub struct NodeConnection {
    /// The node name (e.g., "foo@localhost").
    pub node_name: String,
    /// Current connection state.
    state: Arc<RwLock<ConnectionState>>,
    /// When the connection was established.
    connected_at: Option<Instant>,
    /// Handle to the background task managing this connection.
    task_handle: Option<JoinHandle<()>>,
    /// Channel for sending RPC requests to the background task.
    request_tx: Option<mpsc::Sender<RpcRequest>>,
    /// Information about the peer node.
    peer_node: Option<PeerNode>,
}

impl std::fmt::Debug for NodeConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeConnection")
            .field("node_name", &self.node_name)
            .field("state", &self.state)
            .field("connected_at", &self.connected_at)
            .finish_non_exhaustive()
    }
}

impl NodeConnection {
    /// Creates a new NodeConnection in the Connecting state.
    fn new(node_name: String) -> Self {
        Self {
            node_name,
            state: Arc::new(RwLock::new(ConnectionState::Connecting)),
            connected_at: None,
            task_handle: None,
            request_tx: None,
            peer_node: None,
        }
    }

    /// Returns the current connection state.
    pub async fn state(&self) -> ConnectionState {
        *self.state.read().await
    }

    /// Returns the status of this connection.
    pub async fn status(&self) -> NodeStatus {
        NodeStatus {
            name: self.node_name.clone(),
            state: self.state().await,
            connected_at: self.connected_at,
        }
    }

    /// Sends an RPC request through this connection.
    pub async fn send_request(&self, message: Message) -> ConnectionResult<Term> {
        let request_tx = self
            .request_tx
            .as_ref()
            .ok_or_else(|| ConnectionError::NotConnected {
                node: self.node_name.clone(),
            })?;

        let (response_tx, mut response_rx) = mpsc::channel(1);
        let request = RpcRequest {
            message,
            response_tx,
        };

        request_tx
            .send(request)
            .await
            .map_err(|_| ConnectionError::ConnectionLost {
                node: self.node_name.clone(),
                reason: "request channel closed".to_string(),
            })?;

        match response_rx.recv().await {
            Some(RpcResponse::Success(term)) => Ok(term),
            Some(RpcResponse::Error(err)) => Err(err),
            None => Err(ConnectionError::ConnectionLost {
                node: self.node_name.clone(),
                reason: "response channel closed".to_string(),
            }),
        }
    }

    /// Gracefully shuts down this connection.
    async fn shutdown(&mut self) {
        self.request_tx.take();

        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await;
        }

        *self.state.write().await = ConnectionState::Disconnected;
    }
}

/// Manages connections to multiple Erlang nodes.
pub struct ConnectionManager {
    /// Map of node names to their connections.
    connections: RwLock<HashMap<String, Arc<Mutex<NodeConnection>>>>,
    /// Our local node name.
    local_node_name: String,
}

impl std::fmt::Debug for ConnectionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionManager")
            .field("local_node_name", &self.local_node_name)
            .finish_non_exhaustive()
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new("erl_dist_mcp@localhost".to_string())
    }
}

impl ConnectionManager {
    /// Creates a new ConnectionManager with the given local node name.
    pub fn new(local_node_name: String) -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
            local_node_name,
        }
    }

    /// Connects to an Erlang node.
    ///
    /// # Arguments
    /// * `node_name` - The full node name (e.g., "foo@localhost")
    /// * `cookie` - The Erlang cookie for authentication
    ///
    /// # Errors
    /// Returns an error if:
    /// - Already connected to this node
    /// - Node is unreachable
    /// - Authentication fails
    /// - Handshake fails
    pub async fn connect(&self, node_name: &str, cookie: &str) -> ConnectionResult<()> {
        {
            let connections = self.connections.read().await;
            if let Some(conn) = connections.get(node_name) {
                let state = conn.lock().await.state().await;
                if state == ConnectionState::Connected || state == ConnectionState::Connecting {
                    return Err(ConnectionError::AlreadyConnected {
                        node: node_name.to_string(),
                    });
                }
            }
        }

        let mut node_conn = NodeConnection::new(node_name.to_string());

        let (short_name, host) = parse_node_name(node_name)?;

        let epmd_addr = format!("{}:{}", host, erl_dist::epmd::DEFAULT_EPMD_PORT);
        let epmd_stream =
            TcpStream::connect(&epmd_addr)
                .await
                .map_err(|e| ConnectionError::NodeUnreachable {
                    node: node_name.to_string(),
                    reason: format!("cannot connect to EPMD at {}: {}", epmd_addr, e),
                })?;

        let epmd_client = EpmdClient::new(ClonableStream::new(epmd_stream));
        let node_entry = epmd_client
            .get_node(&short_name)
            .await
            .map_err(|e| ConnectionError::NodeUnreachable {
                node: node_name.to_string(),
                reason: format!("EPMD lookup failed: {}", e),
            })?
            .ok_or_else(|| ConnectionError::NodeUnreachable {
                node: node_name.to_string(),
                reason: "node not registered with EPMD".to_string(),
            })?;

        let node_addr = format!("{}:{}", host, node_entry.port);
        let stream =
            TcpStream::connect(&node_addr)
                .await
                .map_err(|e| ConnectionError::NodeUnreachable {
                    node: node_name.to_string(),
                    reason: format!("cannot connect to node at {}: {}", node_addr, e),
                })?;

        let clonable_stream = ClonableStream::new(stream);

        let local_node_name: NodeName =
            self.local_node_name
                .parse()
                .map_err(|e| ConnectionError::HandshakeFailed {
                    node: node_name.to_string(),
                    reason: format!("invalid local node name: {}", e),
                })?;

        let local_node = LocalNode::new(local_node_name, Creation::random());

        let mut handshake = ClientSideHandshake::new(clonable_stream, local_node, cookie);

        let status = handshake
            .execute_send_name(erl_dist::LOWEST_DISTRIBUTION_PROTOCOL_VERSION)
            .await
            .map_err(|e| ConnectionError::HandshakeFailed {
                node: node_name.to_string(),
                reason: format!("send_name failed: {}", e),
            })?;

        let do_continue = matches!(status, HandshakeStatus::Alive);

        let (stream, peer_node) = handshake.execute_rest(do_continue).await.map_err(|e| {
            let err_str = e.to_string().to_lowercase();
            if err_str.contains("not_allowed") || err_str.contains("authentication") {
                ConnectionError::AuthenticationFailed {
                    node: node_name.to_string(),
                }
            } else {
                ConnectionError::HandshakeFailed {
                    node: node_name.to_string(),
                    reason: format!("handshake failed: {}", e),
                }
            }
        })?;

        let (sender, receiver) = message::channel(stream, peer_node.flags);

        let (request_tx, request_rx) = mpsc::channel::<RpcRequest>(32);

        let state_clone = node_conn.state.clone();
        let node_name_clone = node_name.to_string();
        let task_handle = tokio::spawn(async move {
            connection_task(sender, receiver, request_rx, state_clone, node_name_clone).await;
        });

        node_conn.peer_node = Some(peer_node);
        node_conn.task_handle = Some(task_handle);
        node_conn.request_tx = Some(request_tx);
        node_conn.connected_at = Some(Instant::now());
        *node_conn.state.write().await = ConnectionState::Connected;

        let mut connections = self.connections.write().await;
        connections.insert(node_name.to_string(), Arc::new(Mutex::new(node_conn)));

        Ok(())
    }

    /// Disconnects from an Erlang node.
    ///
    /// # Arguments
    /// * `node_name` - The full node name to disconnect from
    ///
    /// # Errors
    /// Returns an error if not connected to this node.
    pub async fn disconnect(&self, node_name: &str) -> ConnectionResult<()> {
        let conn = {
            let mut connections = self.connections.write().await;
            connections.remove(node_name)
        };

        match conn {
            Some(conn) => {
                let mut conn = conn.lock().await;
                conn.shutdown().await;
                Ok(())
            }
            None => Err(ConnectionError::NotConnected {
                node: node_name.to_string(),
            }),
        }
    }

    /// Lists all current connections and their statuses.
    pub async fn list_connections(&self) -> Vec<NodeStatus> {
        let connections = self.connections.read().await;
        let mut statuses = Vec::with_capacity(connections.len());

        for conn in connections.values() {
            let conn = conn.lock().await;
            statuses.push(conn.status().await);
        }

        statuses
    }

    /// Gets a reference to a connection if it exists.
    pub async fn get_connection(&self, node_name: &str) -> Option<Arc<Mutex<NodeConnection>>> {
        let connections = self.connections.read().await;
        connections.get(node_name).cloned()
    }

    /// Checks if connected to a specific node.
    pub async fn is_connected(&self, node_name: &str) -> bool {
        if let Some(conn) = self.get_connection(node_name).await {
            let conn = conn.lock().await;
            conn.state().await == ConnectionState::Connected
        } else {
            false
        }
    }

    /// Gets the peer node's creation value, needed for constructing valid PIDs.
    pub async fn get_peer_creation(&self, node_name: &str) -> Option<u32> {
        let conn = self.get_connection(node_name).await?;
        let conn = conn.lock().await;
        conn.peer_node
            .as_ref()
            .and_then(|p| p.creation)
            .map(|c| c.get())
    }
}

/// Parses a node name into (short_name, host).
fn parse_node_name(node_name: &str) -> ConnectionResult<(String, String)> {
    let parts: Vec<&str> = node_name.split('@').collect();
    if parts.len() != 2 {
        return Err(ConnectionError::HandshakeFailed {
            node: node_name.to_string(),
            reason: "invalid node name format, expected 'name@host'".to_string(),
        });
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

/// Background task that manages a node connection.
async fn connection_task<T>(
    mut sender: Sender<T>,
    mut receiver: Receiver<T>,
    mut request_rx: mpsc::Receiver<RpcRequest>,
    state: Arc<RwLock<ConnectionState>>,
    node_name: String,
) where
    T: AsyncRead + AsyncWrite + Unpin + Clone,
{
    let mut tick_interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
    let mut pending_response: Option<mpsc::Sender<RpcResponse>> = None;

    loop {
        tokio::select! {
            request = request_rx.recv() => {
                match request {
                    Some(rpc_request) => {
                        if let Err(e) = sender.send(rpc_request.message).await {
                            let err = ConnectionError::ConnectionLost {
                                node: node_name.clone(),
                                reason: format!("send failed: {}", e),
                            };
                            let _ = rpc_request.response_tx.send(RpcResponse::Error(err)).await;
                            break;
                        }
                        pending_response = Some(rpc_request.response_tx);
                    }
                    None => {
                        break;
                    }
                }
            }

            msg = receiver.recv() => {
                match msg {
                    Ok(message) => {
                        match message {
                            Message::Tick => {
                                tracing::trace!("Received tick from {}", node_name);
                            }
                            _ => {
                                if let Some(tx) = pending_response.take() {
                                    let response = match extract_message_term(message) {
                                        Some(term) => RpcResponse::Success(extract_gen_call_result(term)),
                                        None => RpcResponse::Error(ConnectionError::ConnectionLost {
                                            node: node_name.clone(),
                                            reason: "received non-send message type".to_string(),
                                        }),
                                    };
                                    let _ = tx.send(response).await;
                                } else {
                                    tracing::debug!("Received unsolicited message from {}: {:?}", node_name, message);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Error receiving from {}: {}", node_name, e);
                        if let Some(tx) = pending_response.take() {
                            let _ = tx.send(RpcResponse::Error(ConnectionError::ConnectionLost {
                                node: node_name.clone(),
                                reason: format!("receive error: {}", e),
                            })).await;
                        }
                        break;
                    }
                }
            }

            _ = tick_interval.tick() => {
                if let Err(e) = sender.send(Message::Tick).await {
                    tracing::error!("Failed to send tick to {}: {}", node_name, e);
                    break;
                }
            }
        }
    }

    *state.write().await = ConnectionState::Disconnected;
    tracing::info!("Connection task for {} terminated", node_name);
}

/// Extract the Term payload from a received Message.
fn extract_message_term(message: Message) -> Option<Term> {
    match message {
        Message::Send(s) => Some(s.message),
        Message::SendSender(s) => Some(s.message),
        Message::SendTt(s) => Some(s.message),
        Message::SendSenderTt(s) => Some(s.message),
        Message::RegSend(s) => Some(s.message),
        Message::RegSendTt(s) => Some(s.message),
        Message::AliasSend(s) => Some(s.message),
        Message::AliasSendTt(s) => Some(s.message),
        _ => None,
    }
}

/// Extract the result from a `$gen_call` response tuple `{Ref, Result}`.
fn extract_gen_call_result(term: Term) -> Term {
    if let Term::Tuple(ref t) = term
        && t.elements.len() == 2
    {
        return t.elements[1].clone();
    }
    term
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_node_name_valid() {
        let (name, host) = parse_node_name("foo@localhost").unwrap();
        assert_eq!(name, "foo");
        assert_eq!(host, "localhost");
    }

    #[test]
    fn parse_node_name_with_domain() {
        let (name, host) = parse_node_name("myapp@server.example.com").unwrap();
        assert_eq!(name, "myapp");
        assert_eq!(host, "server.example.com");
    }

    #[test]
    fn parse_node_name_invalid_no_at() {
        let result = parse_node_name("foobar");
        assert!(result.is_err());
    }

    #[test]
    fn parse_node_name_invalid_multiple_at() {
        let result = parse_node_name("foo@bar@baz");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn connection_manager_new() {
        let manager = ConnectionManager::new("test@localhost".to_string());
        assert!(manager.list_connections().await.is_empty());
    }

    #[tokio::test]
    async fn connection_manager_default() {
        let manager = ConnectionManager::default();
        assert_eq!(manager.local_node_name, "erl_dist_mcp@localhost");
    }

    #[tokio::test]
    async fn connection_state_display() {
        assert_eq!(ConnectionState::Connecting.to_string(), "connecting");
        assert_eq!(ConnectionState::Connected.to_string(), "connected");
        assert_eq!(ConnectionState::Disconnected.to_string(), "disconnected");
        assert_eq!(ConnectionState::Failed.to_string(), "failed");
    }

    #[tokio::test]
    async fn node_connection_initial_state() {
        let conn = NodeConnection::new("test@localhost".to_string());
        assert_eq!(conn.node_name, "test@localhost");
        assert_eq!(conn.state().await, ConnectionState::Connecting);
        assert!(conn.connected_at.is_none());
    }

    #[tokio::test]
    async fn disconnect_not_connected() {
        let manager = ConnectionManager::default();
        let result = manager.disconnect("nonexistent@localhost").await;
        assert!(matches!(result, Err(ConnectionError::NotConnected { .. })));
    }

    #[tokio::test]
    async fn get_connection_not_found() {
        let manager = ConnectionManager::default();
        let result = manager.get_connection("nonexistent@localhost").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn is_connected_false_when_not_connected() {
        let manager = ConnectionManager::default();
        assert!(!manager.is_connected("foo@localhost").await);
    }
}
