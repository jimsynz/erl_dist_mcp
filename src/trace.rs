//! Tracing infrastructure for function call tracing.
//!
//! This module provides the TraceManager which tracks active trace sessions
//! and manages tracing lifecycle (start, stop, collect results).

use crate::connection::ConnectionManager;
use crate::error::{RpcError, RpcResult};
use crate::rpc;
use eetf::{Atom, FixInteger, List, Term, Tuple};
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Parameters for starting a trace.
pub struct TraceParams<'a> {
    pub node: &'a str,
    pub module: &'a str,
    pub function: Option<&'a str>,
    pub arity: Option<u8>,
    pub max_traces: usize,
    pub duration_ms: u64,
}

/// A single trace session.
#[derive(Debug, Clone)]
pub struct TraceSession {
    /// Unique identifier for this session.
    pub id: String,
    /// The node being traced.
    pub node: String,
    /// Path to the trace file (for dbg fallback).
    pub trace_file: Option<PathBuf>,
    /// When the session was started.
    pub started_at: SystemTime,
    /// Maximum number of traces to collect.
    pub max_traces: usize,
    /// Number of traces collected so far.
    pub collected: usize,
    /// Whether recon_trace is being used (true) or dbg fallback (false).
    pub using_recon: bool,
    /// Duration in milliseconds (for automatic cleanup).
    pub duration_ms: u64,
    /// Offset in trace file for incremental reads (dbg only).
    pub file_offset: u64,
}

/// A single trace event captured during tracing.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TraceEvent {
    Call {
        pid: String,
        module: String,
        function: String,
        args: String,
    },
    Return {
        pid: String,
        module: String,
        function: String,
        arity: u8,
        result: String,
    },
    Exception {
        pid: String,
        module: String,
        function: String,
        arity: u8,
        class: String,
        value: String,
    },
}

/// Manages active trace sessions across multiple nodes.
#[derive(Debug, Default)]
pub struct TraceManager {
    sessions: Arc<RwLock<HashMap<String, TraceSession>>>,
}

impl TraceManager {
    /// Creates a new trace manager.
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Checks if recon library is available on the target node.
    pub async fn check_recon_available(
        &self,
        connection_manager: &ConnectionManager,
        node: &str,
    ) -> RpcResult<bool> {
        // Call code:which(recon_trace) - returns non_existing atom if not available
        let result = rpc::rpc_call(
            connection_manager,
            node,
            "code",
            "which",
            vec![Term::from(Atom::from("recon_trace"))],
            Some(5000),
        )
        .await?;

        // If result is the atom 'non_existing', recon is not available
        Ok(!matches!(result, Term::Atom(ref a) if a.name == "non_existing"))
    }

    /// Starts a trace session.
    pub async fn start_trace(
        &self,
        connection_manager: &ConnectionManager,
        params: TraceParams<'_>,
    ) -> RpcResult<String> {
        // Generate unique trace ID
        let trace_id = format!("trace_{}_{}", params.node, Uuid::new_v4());

        // Check if recon is available
        let using_recon = self
            .check_recon_available(connection_manager, params.node)
            .await?;

        if using_recon {
            // Start recon_trace
            self.start_recon_trace(connection_manager, &params).await?;

            // Store session without trace file (recon doesn't use files)
            let session = TraceSession {
                id: trace_id.clone(),
                node: params.node.to_string(),
                trace_file: None,
                started_at: SystemTime::now(),
                max_traces: params.max_traces,
                collected: 0,
                using_recon: true,
                duration_ms: params.duration_ms,
                file_offset: 0,
            };

            self.sessions
                .write()
                .await
                .insert(trace_id.clone(), session);
        } else {
            // Create temporary file for dbg trace output
            let trace_file = std::env::temp_dir().join(format!("{}.trace", trace_id));

            // Start dbg trace
            self.start_dbg_trace(connection_manager, &params, &trace_file)
                .await?;

            // Store session with trace file
            let session = TraceSession {
                id: trace_id.clone(),
                node: params.node.to_string(),
                trace_file: Some(trace_file),
                started_at: SystemTime::now(),
                max_traces: params.max_traces,
                collected: 0,
                using_recon: false,
                duration_ms: params.duration_ms,
                file_offset: 0,
            };

            self.sessions
                .write()
                .await
                .insert(trace_id.clone(), session);
        }

        Ok(trace_id)
    }

    /// Starts recon_trace on the target node.
    async fn start_recon_trace(
        &self,
        connection_manager: &ConnectionManager,
        params: &TraceParams<'_>,
    ) -> RpcResult<()> {
        // Build trace spec: {module, function, arity}
        let tspec = build_trace_spec(params.module, params.function, params.arity);

        // Rate limit: {max_traces, duration_ms}
        let max = Term::from(Tuple::from(vec![
            Term::from(FixInteger::from(params.max_traces as i32)),
            Term::from(FixInteger::from(params.duration_ms as i32)),
        ]));

        // Build opts: [] (use defaults)
        let opts = Term::from(List::from(vec![]));

        // Call recon_trace:calls(TSpec, Max, Opts)
        // Extend timeout to allow for the trace duration
        rpc::rpc_call(
            connection_manager,
            params.node,
            "recon_trace",
            "calls",
            vec![tspec, max, opts],
            Some(params.duration_ms + 5000),
        )
        .await?;

        Ok(())
    }

    /// Starts dbg trace on the target node with file output.
    async fn start_dbg_trace(
        &self,
        connection_manager: &ConnectionManager,
        params: &TraceParams<'_>,
        trace_file: &Path,
    ) -> RpcResult<()> {
        // Start file tracer: dbg:tracer(file, "path")
        let file_path = trace_file.to_str().ok_or_else(|| RpcError::EncodeError {
            module: "dbg".to_string(),
            function: "tracer".to_string(),
            reason: "Invalid trace file path".to_string(),
        })?;

        rpc::rpc_call(
            connection_manager,
            params.node,
            "dbg",
            "tracer",
            vec![
                Term::from(Atom::from("file")),
                Term::from(eetf::Binary::from(file_path.as_bytes().to_vec())),
            ],
            Some(5000),
        )
        .await?;

        // Enable tracing on all processes: dbg:p(all, c)
        rpc::rpc_call(
            connection_manager,
            params.node,
            "dbg",
            "p",
            vec![Term::from(Atom::from("all")), Term::from(Atom::from("c"))],
            Some(5000),
        )
        .await?;

        // Build match spec for exception trace (captures args, returns, exceptions)
        let match_spec = build_exception_trace_match_spec();

        // Set trace pattern: dbg:tpl(Module, Function, MatchSpec)
        let func_term = params
            .function
            .map(|f| Term::from(Atom::from(f)))
            .unwrap_or_else(|| Term::from(Atom::from("_")));

        let arity_term = params
            .arity
            .map(|a| Term::from(FixInteger::from(a as i32)))
            .unwrap_or_else(|| Term::from(Atom::from("_")));

        rpc::rpc_call(
            connection_manager,
            params.node,
            "dbg",
            "tpl",
            vec![
                Term::from(Atom::from(params.module)),
                func_term,
                arity_term,
                match_spec,
            ],
            Some(5000),
        )
        .await?;

        Ok(())
    }

    /// Gets a trace session by ID.
    pub async fn get_session(&self, trace_id: &str) -> Option<TraceSession> {
        self.sessions.read().await.get(trace_id).cloned()
    }

    /// Removes and returns a trace session.
    pub async fn remove_session(&self, trace_id: &str) -> Option<TraceSession> {
        self.sessions.write().await.remove(trace_id)
    }

    /// Lists all sessions for a given node.
    pub async fn list_node_sessions(&self, node: &str) -> Vec<TraceSession> {
        self.sessions
            .read()
            .await
            .values()
            .filter(|s| s.node == node)
            .cloned()
            .collect()
    }

    /// Stops a specific trace session or all sessions on a node.
    pub async fn stop_trace(
        &self,
        connection_manager: &ConnectionManager,
        node: &str,
        trace_id: Option<&str>,
    ) -> RpcResult<usize> {
        // Collect sessions to stop
        let sessions_to_stop = if let Some(id) = trace_id {
            // Stop specific trace
            if let Some(session) = self.remove_session(id).await {
                vec![session]
            } else {
                return Err(RpcError::BadRpc {
                    node: node.to_string(),
                    module: "trace_manager".to_string(),
                    function: "stop_trace".to_string(),
                    reason: format!("Trace session not found: {}", id),
                });
            }
        } else {
            // Stop all traces on this node
            let all_sessions = self.list_node_sessions(node).await;

            // Remove them from the map
            let mut sessions_guard = self.sessions.write().await;
            for session in &all_sessions {
                sessions_guard.remove(&session.id);
            }
            drop(sessions_guard);

            all_sessions
        };

        if sessions_to_stop.is_empty() {
            return Ok(0);
        }

        // Stop traces based on which backend was used
        let using_recon = sessions_to_stop[0].using_recon;

        if using_recon {
            // Call recon_trace:clear()
            rpc::rpc_call(
                connection_manager,
                node,
                "recon_trace",
                "clear",
                vec![],
                Some(5000),
            )
            .await?;
        } else {
            // Call dbg:stop_clear()
            rpc::rpc_call(
                connection_manager,
                node,
                "dbg",
                "stop_clear",
                vec![],
                Some(5000),
            )
            .await?;
        }

        // Calculate total traces collected
        let total_collected: usize = sessions_to_stop.iter().map(|s| s.collected).sum();

        Ok(total_collected)
    }

    /// Retrieves trace results for a session.
    pub async fn get_trace_results(
        &self,
        trace_id: &str,
        limit: Option<usize>,
        formatter: &dyn crate::formatter::TermFormatter,
    ) -> RpcResult<Vec<TraceEvent>> {
        // Get the session
        let mut session = self
            .get_session(trace_id)
            .await
            .ok_or_else(|| RpcError::BadRpc {
                node: "".to_string(),
                module: "trace_manager".to_string(),
                function: "get_trace_results".to_string(),
                reason: format!("Trace session not found: {}", trace_id),
            })?;

        // recon doesn't write to files, so no results to retrieve
        if session.using_recon {
            return Err(RpcError::BadRpc {
                node: session.node.clone(),
                module: "trace_manager".to_string(),
                function: "get_trace_results".to_string(),
                reason: "recon_trace results are written to stdout, not available for retrieval"
                    .to_string(),
            });
        }

        // Get trace file
        let trace_file = session
            .trace_file
            .as_ref()
            .ok_or_else(|| RpcError::BadRpc {
                node: session.node.clone(),
                module: "trace_manager".to_string(),
                function: "get_trace_results".to_string(),
                reason: "No trace file available".to_string(),
            })?;

        // Parse trace file incrementally from last offset
        let events = self
            .parse_trace_file(trace_file, session.file_offset, limit, formatter)
            .await?;

        // Update session with new offset and collected count
        if !events.is_empty() {
            session.collected += events.len();
            self.sessions
                .write()
                .await
                .insert(trace_id.to_string(), session);
        }

        Ok(events)
    }

    /// Parses a dbg trace file and extracts trace events.
    async fn parse_trace_file(
        &self,
        trace_file: &Path,
        start_offset: u64,
        limit: Option<usize>,
        formatter: &dyn crate::formatter::TermFormatter,
    ) -> RpcResult<Vec<TraceEvent>> {
        // The trace file is created by dbg on the target node's filesystem.
        // It may not exist locally if the node is remote or no events were captured yet.
        if !trace_file.exists() {
            return Ok(Vec::new());
        }

        let mut file = std::fs::File::open(trace_file).map_err(|e| RpcError::BadRpc {
            node: "".to_string(),
            module: "trace_manager".to_string(),
            function: "parse_trace_file".to_string(),
            reason: format!("Failed to open trace file: {}", e),
        })?;

        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(start_offset))
            .map_err(|e| RpcError::BadRpc {
                node: "".to_string(),
                module: "trace_manager".to_string(),
                function: "parse_trace_file".to_string(),
                reason: format!("Failed to seek trace file: {}", e),
            })?;

        let mut reader = std::io::BufReader::new(file);
        let mut events = Vec::new();
        let max = limit.unwrap_or(usize::MAX);

        // Parse trace tuples from file
        while events.len() < max {
            let term = match Term::decode(&mut reader) {
                Ok(t) => t,
                Err(_) => break, // EOF or parse error
            };

            if let Some(event) = self.parse_trace_tuple(&term, formatter)? {
                events.push(event);
            }
        }

        Ok(events)
    }

    /// Parses a single trace tuple into a TraceEvent.
    fn parse_trace_tuple(
        &self,
        term: &Term,
        formatter: &dyn crate::formatter::TermFormatter,
    ) -> RpcResult<Option<TraceEvent>> {
        // Extract tuple
        let tuple = match term {
            Term::Tuple(t) => &t.elements,
            _ => return Ok(None),
        };

        if tuple.len() < 4 {
            return Ok(None);
        }

        // Check trace tag
        let tag = match &tuple[0] {
            Term::Atom(a) => &a.name,
            _ => return Ok(None),
        };

        if tag != "trace" && tag != "trace_ts" {
            return Ok(None);
        }

        // Extract PID
        let pid = match &tuple[1] {
            Term::Pid(p) => format!("<{}.{}.{}>", p.node.name, p.id, p.serial),
            _ => return Ok(None),
        };

        // Extract event type
        let event_type = match &tuple[2] {
            Term::Atom(a) => &a.name,
            _ => return Ok(None),
        };

        match event_type.as_str() {
            "call" => {
                // {trace, Pid, call, {M, F, Args}}
                let mfa_tuple = match &tuple[3] {
                    Term::Tuple(t) => &t.elements,
                    _ => return Ok(None),
                };

                if mfa_tuple.len() < 3 {
                    return Ok(None);
                }

                let module = match &mfa_tuple[0] {
                    Term::Atom(a) => a.name.clone(),
                    _ => return Ok(None),
                };

                let function = match &mfa_tuple[1] {
                    Term::Atom(a) => a.name.clone(),
                    _ => return Ok(None),
                };

                let args = formatter.format_term(&mfa_tuple[2]);

                Ok(Some(TraceEvent::Call {
                    pid,
                    module,
                    function,
                    args,
                }))
            }
            "return_from" => {
                // {trace, Pid, return_from, {M, F, Arity}, Result}
                if tuple.len() < 5 {
                    return Ok(None);
                }

                let mfa_tuple = match &tuple[3] {
                    Term::Tuple(t) => &t.elements,
                    _ => return Ok(None),
                };

                if mfa_tuple.len() < 3 {
                    return Ok(None);
                }

                let module = match &mfa_tuple[0] {
                    Term::Atom(a) => a.name.clone(),
                    _ => return Ok(None),
                };

                let function = match &mfa_tuple[1] {
                    Term::Atom(a) => a.name.clone(),
                    _ => return Ok(None),
                };

                let arity = match &mfa_tuple[2] {
                    Term::FixInteger(i) => i.value as u8,
                    _ => return Ok(None),
                };

                let result = formatter.format_term(&tuple[4]);

                Ok(Some(TraceEvent::Return {
                    pid,
                    module,
                    function,
                    arity,
                    result,
                }))
            }
            "exception_from" => {
                // {trace, Pid, exception_from, {M, F, Arity}, {Class, Value}}
                if tuple.len() < 5 {
                    return Ok(None);
                }

                let mfa_tuple = match &tuple[3] {
                    Term::Tuple(t) => &t.elements,
                    _ => return Ok(None),
                };

                if mfa_tuple.len() < 3 {
                    return Ok(None);
                }

                let module = match &mfa_tuple[0] {
                    Term::Atom(a) => a.name.clone(),
                    _ => return Ok(None),
                };

                let function = match &mfa_tuple[1] {
                    Term::Atom(a) => a.name.clone(),
                    _ => return Ok(None),
                };

                let arity = match &mfa_tuple[2] {
                    Term::FixInteger(i) => i.value as u8,
                    _ => return Ok(None),
                };

                let exception = match &tuple[4] {
                    Term::Tuple(t) => &t.elements,
                    _ => return Ok(None),
                };

                if exception.len() < 2 {
                    return Ok(None);
                }

                let class = match &exception[0] {
                    Term::Atom(a) => a.name.clone(),
                    _ => return Ok(None),
                };

                let value = formatter.format_term(&exception[1]);

                Ok(Some(TraceEvent::Exception {
                    pid,
                    module,
                    function,
                    arity,
                    class,
                    value,
                }))
            }
            _ => Ok(None),
        }
    }
}

/// Builds a trace specification tuple for the given module/function/arity.
fn build_trace_spec(module: &str, function: Option<&str>, arity: Option<u8>) -> Term {
    let module_term = Term::from(Atom::from(module));

    let function_term = function
        .map(|f| Term::from(Atom::from(f)))
        .unwrap_or_else(|| Term::from(Atom::from("_")));

    let arity_term = arity
        .map(|a| Term::from(FixInteger::from(a as i32)))
        .unwrap_or_else(|| Term::from(Atom::from("_")));

    Term::from(Tuple::from(vec![module_term, function_term, arity_term]))
}

/// Builds the exception trace match specification for dbg.
/// This is equivalent to dbg:fun2ms(fun(_) -> exception_trace() end).
fn build_exception_trace_match_spec() -> Term {
    // Match spec format: [{Pattern, Guards, Body}]
    // For exception_trace: [{['_'], [], [{exception_trace}]}]
    let pattern = Term::from(List::from(vec![Term::from(Atom::from("_"))]));
    let guards = Term::from(List::from(vec![]));
    let body = Term::from(List::from(vec![Term::from(Tuple::from(vec![Term::from(
        Atom::from("exception_trace"),
    )]))]));

    let match_tuple = Term::from(Tuple::from(vec![pattern, guards, body]));
    Term::from(List::from(vec![match_tuple]))
}
