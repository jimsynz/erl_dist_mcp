//! MCP Server implementation for Erlang Distribution.
//!
//! This module provides the MCP server that exposes tools for interacting
//! with connected Erlang nodes.

use crate::connection::{ConnectionManager, ConnectionState};
use crate::formatter::{TermFormatter, get_formatter};
use crate::trace::{TraceManager, TraceParams};
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, Content, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
};
use rmcp::{ErrorData as McpError, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// The output format mode for displaying Erlang terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FormatterMode {
    /// Standard Erlang syntax.
    #[default]
    Erlang,
    /// Elixir syntax.
    Elixir,
    /// Gleam syntax.
    Gleam,
    /// LFE (Lisp Flavoured Erlang) syntax.
    Lfe,
}

impl std::fmt::Display for FormatterMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FormatterMode::Erlang => write!(f, "erlang"),
            FormatterMode::Elixir => write!(f, "elixir"),
            FormatterMode::Gleam => write!(f, "gleam"),
            FormatterMode::Lfe => write!(f, "lfe"),
        }
    }
}

impl std::str::FromStr for FormatterMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "erlang" => Ok(FormatterMode::Erlang),
            "elixir" => Ok(FormatterMode::Elixir),
            "gleam" => Ok(FormatterMode::Gleam),
            "lfe" => Ok(FormatterMode::Lfe),
            _ => Err(format!(
                "invalid mode '{}', expected one of: erlang, elixir, gleam, lfe",
                s
            )),
        }
    }
}

/// Elixir module source that gets eval'd on the remote node to install a log handler.
/// Defines ErlDistMcp.LogHandler which uses a named ETS table as a ring buffer.
const LOG_HANDLER_SOURCE: &str = r##"
defmodule ErlDistMcp.LogHandler do
  @table :erl_dist_mcp_log_buffer
  @default_max 500

  def install(max_events \\ @default_max) do
    case :ets.info(@table) do
      :undefined ->
        :ets.new(@table, [:named_table, :ordered_set, :public])
        :persistent_term.put({__MODULE__, :max_events}, max_events)
        :persistent_term.put({__MODULE__, :counter}, :atomics.new(1, []))
        :logger.add_handler(:erl_dist_mcp, __MODULE__, %{})
        owner = spawn(fn -> table_owner_loop() end)
        :ets.give_away(@table, owner, nil)
        :ok

      _ ->
        :already_installed
    end
  end

  defp table_owner_loop do
    receive do
      :stop -> :ok
    end
  end

  def log(%{level: level, msg: msg, meta: meta}, _config) do
    counter = :persistent_term.get({__MODULE__, :counter})
    max = :persistent_term.get({__MODULE__, :max_events})
    idx = :atomics.add_get(counter, 1, 1)

    message =
      case msg do
        {:string, s} -> IO.chardata_to_string(s)
        {:report, report} -> inspect(report)
        {:format, fmt, args} -> :io_lib.format(fmt, args) |> IO.chardata_to_string()
      end

    mfa =
      case Map.get(meta, :mfa) do
        {m, f, a} -> "#{inspect(m)}.#{f}/#{a}"
        _ -> nil
      end

    event = %{
      level: level,
      msg: message,
      time: Map.get(meta, :time, System.system_time(:microsecond)),
      meta: %{pid: meta |> Map.get(:pid) |> inspect(), mfa: mfa}
    }

    :ets.insert(@table, {idx, event})

    if idx > max do
      :ets.delete(@table, idx - max)
    end

    :ok
  end

  def get_events(limit) do
    size = :ets.info(@table, :size)

    events =
      case size do
        0 ->
          []

        _ ->
          last = :ets.last(@table)
          take = min(limit, size)
          collect_events(@table, last, take, [])
      end

    events
  end

  def uninstall do
    :logger.remove_handler(:erl_dist_mcp)
    :ets.delete(@table)
    :persistent_term.erase({__MODULE__, :max_events})
    :persistent_term.erase({__MODULE__, :counter})
    :ok
  rescue
    _ -> :ok
  end

  defp collect_events(_table, _key, 0, acc), do: acc

  defp collect_events(table, key, remaining, acc) do
    case :ets.lookup(table, key) do
      [{_, event}] ->
        prev = :ets.prev(table, key)

        case prev do
          :"$end_of_table" -> [event | acc]
          _ -> collect_events(table, prev, remaining - 1, [event | acc])
        end

      [] ->
        acc
    end
  end
end

ErlDistMcp.LogHandler.install()
"##;

/// State shared by the MCP server.
pub struct ServerState {
    /// The connection manager for Erlang nodes.
    pub connection_manager: ConnectionManager,
    /// The current output formatter mode.
    pub mode: RwLock<FormatterMode>,
    /// The current formatter instance (cached based on mode).
    pub formatter: RwLock<Box<dyn TermFormatter>>,
    /// Whether code evaluation is allowed.
    pub allow_eval: bool,
    /// Trace session manager.
    pub trace_manager: TraceManager,
}

impl ServerState {
    /// Creates a new server state.
    pub fn new(mode: FormatterMode, allow_eval: bool) -> Self {
        let formatter = get_formatter(mode);
        Self {
            connection_manager: ConnectionManager::default(),
            mode: RwLock::new(mode),
            formatter: RwLock::new(formatter),
            allow_eval,
            trace_manager: TraceManager::new(),
        }
    }

    /// Sets the formatter mode and updates the cached formatter.
    pub async fn set_mode(&self, mode: FormatterMode) {
        let mut mode_guard = self.mode.write().await;
        let mut formatter_guard = self.formatter.write().await;
        *mode_guard = mode;
        *formatter_guard = get_formatter(mode);
    }

    /// Gets the current formatter mode.
    pub async fn get_mode(&self) -> FormatterMode {
        *self.mode.read().await
    }
}

impl std::fmt::Debug for ServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerState")
            .field("allow_eval", &self.allow_eval)
            .finish_non_exhaustive()
    }
}

/// The MCP server for Erlang Distribution.
#[derive(Clone)]
pub struct ErlDistMcpServer {
    /// Shared server state.
    state: Arc<ServerState>,
    /// Tool router for handling tool calls.
    /// The router is used by rmcp macros at runtime for dispatching tool calls.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for ErlDistMcpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErlDistMcpServer")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// Request parameters for the connect_node tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ConnectNodeRequest {
    /// The full node name to connect to (e.g., "myapp@localhost").
    #[schemars(description = "The full node name to connect to (e.g., 'myapp@localhost')")]
    pub node: String,
    /// The Erlang cookie for authentication.
    #[schemars(description = "The Erlang cookie for authentication")]
    pub cookie: String,
    /// An optional alias for the connection (currently unused, reserved for future use).
    #[schemars(description = "An optional alias for the connection (reserved for future use)")]
    #[serde(default)]
    pub alias: Option<String>,
}

/// Response from the connect_node tool.
#[derive(Debug, Serialize)]
struct ConnectNodeResponse {
    success: bool,
    node: String,
    message: String,
}

/// Request parameters for the disconnect_node tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DisconnectNodeRequest {
    /// The node name to disconnect from.
    #[schemars(description = "The node name to disconnect from")]
    pub node: String,
}

/// Response from the disconnect_node tool.
#[derive(Debug, Serialize)]
struct DisconnectNodeResponse {
    success: bool,
    message: String,
}

/// Status of a single node in the list_nodes response.
#[derive(Debug, Serialize)]
struct NodeInfo {
    name: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    connected_at: Option<String>,
}

/// Response from the list_nodes tool.
#[derive(Debug, Serialize)]
struct ListNodesResponse {
    nodes: Vec<NodeInfo>,
}

/// Request parameters for the set_mode tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetModeRequest {
    /// The output format mode to use.
    #[schemars(description = "The output format mode: erlang, elixir, gleam, or lfe")]
    pub mode: String,
}

/// Response from the set_mode tool.
#[derive(Debug, Serialize)]
struct SetModeResponse {
    success: bool,
    mode: String,
    message: String,
}

/// Request parameters for the list_processes tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListProcessesRequest {
    /// The node name to query.
    #[schemars(description = "The node name to query")]
    pub node: String,
    /// Maximum number of processes to return (default 100).
    #[schemars(description = "Maximum number of processes to return (default 100)")]
    #[serde(default = "default_process_limit")]
    pub limit: usize,
}

fn default_process_limit() -> usize {
    100
}

/// Information about a single process.
#[derive(Debug, Serialize)]
struct ProcessInfo {
    pid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    registered_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_function: Option<String>,
    memory: u64,
    reductions: u64,
    message_queue_len: u64,
}

/// Response from the list_processes tool.
#[derive(Debug, Serialize)]
struct ListProcessesResponse {
    node: String,
    processes: Vec<ProcessInfo>,
    total_count: usize,
}

/// Request parameters for the get_process_info tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetProcessInfoRequest {
    /// The node name to query.
    #[schemars(description = "The node name to query")]
    pub node: String,
    /// The PID to inspect. Accepts formats: <0.123.0>, #PID<0.123.0>, or 0.123.0
    #[schemars(
        description = "The PID to inspect. Accepts formats: <0.123.0>, #PID<0.123.0>, or 0.123.0"
    )]
    pub pid: String,
}

/// Response from the get_process_info tool.
#[derive(Debug, Serialize)]
struct GetProcessInfoResponse {
    node: String,
    pid: String,
    info: serde_json::Value,
}

/// Request parameters for the top_processes tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TopProcessesRequest {
    /// The node name to query.
    #[schemars(description = "The node name to query")]
    pub node: String,
    /// Sort key: memory, reductions, or message_queue
    #[schemars(description = "Sort by: 'memory', 'reductions', or 'message_queue'")]
    pub sort_by: String,
    /// Maximum number of processes to return (default 10).
    #[schemars(description = "Maximum number of processes to return (default 10)")]
    #[serde(default = "default_top_processes_limit")]
    pub limit: usize,
}

/// Request parameters for the find_process tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindProcessRequest {
    /// The node name to query.
    #[schemars(description = "The node name to query")]
    pub node: String,
    /// Search by registered name (substring, case-insensitive).
    #[schemars(
        description = "Search by registered name (substring, case-insensitive). At least one of name or module must be provided."
    )]
    #[serde(default)]
    pub name: Option<String>,
    /// Search by current function module (exact match, case-sensitive).
    #[schemars(
        description = "Search by current function module (exact match, case-sensitive). At least one of name or module must be provided."
    )]
    #[serde(default)]
    pub module: Option<String>,
}

/// Response from the find_process tool.
#[derive(Debug, Serialize)]
struct FindProcessResponse {
    node: String,
    processes: Vec<FoundProcessInfo>,
    total_found: usize,
}

/// Information about a found process.
#[derive(Debug, Serialize)]
struct FoundProcessInfo {
    pid: String,
    registered_name: Option<String>,
    current_function: Option<String>,
    memory: u64,
}

/// Request parameters for the get_message_queue tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetMessageQueueRequest {
    /// The node name to query.
    #[schemars(description = "The node name to query")]
    pub node: String,
    /// The process PID (formats: <0.123.0>, #PID<0.123.0>, or 0.123.0).
    #[schemars(description = "The process PID (formats: <0.123.0>, #PID<0.123.0>, or 0.123.0)")]
    pub pid: String,
    /// Maximum number of messages to return (default 10).
    #[schemars(description = "Maximum number of messages to return (default 10)")]
    #[serde(default = "default_message_queue_limit")]
    pub limit: usize,
}

/// Response from the get_message_queue tool.
#[derive(Debug, Serialize)]
struct GetMessageQueueResponse {
    node: String,
    pid: String,
    queue_length: u64,
    messages: Vec<serde_json::Value>,
    warning: Option<String>,
}

fn default_message_queue_limit() -> usize {
    10
}

fn default_top_processes_limit() -> usize {
    10
}

/// Request parameters for the list_applications tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListApplicationsRequest {
    /// The node name to query.
    #[schemars(description = "The node name to query")]
    pub node: String,
}

/// Response from the list_applications tool.
#[derive(Debug, Serialize)]
struct ListApplicationsResponse {
    node: String,
    applications: Vec<ApplicationInfo>,
}

/// Information about a running application.
#[derive(Debug, Serialize)]
struct ApplicationInfo {
    name: String,
    description: String,
    version: String,
}

/// Request for the get_application_info tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetApplicationInfoRequest {
    /// The node name to query.
    #[schemars(description = "The node name to query")]
    pub node: String,
    /// The application name to inspect.
    #[schemars(description = "The application name (e.g., 'kernel', 'stdlib')")]
    pub app: String,
}

/// Response from the get_application_info tool.
#[derive(Debug, Serialize)]
struct GetApplicationInfoResponse {
    node: String,
    app: String,
    metadata: serde_json::Value,
    environment: serde_json::Value,
}

/// Request for the get_supervision_tree tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetSupervisionTreeRequest {
    /// The node name to query.
    #[schemars(description = "The node name to query")]
    pub node: String,
    /// The supervisor root (PID like <0.123.0> or registered name like 'my_app_sup').
    #[schemars(description = "The supervisor root (PID or registered name)")]
    pub root: String,
}

/// Response from the get_supervision_tree tool.
#[derive(Debug, Serialize)]
struct GetSupervisionTreeResponse {
    node: String,
    root: String,
    tree: SupervisionTreeNode,
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
}

/// A node in the supervision tree.
#[derive(Debug, Clone, Serialize)]
struct SupervisionTreeNode {
    id: String,
    pid: Option<String>,
    #[serde(rename = "type")]
    child_type: String,
    modules: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    children: Vec<SupervisionTreeNode>,
}

/// Response from the top_processes tool.
#[derive(Debug, Serialize)]
struct TopProcessesResponse {
    node: String,
    sort_by: String,
    processes: Vec<TopProcessInfo>,
    used_recon: bool,
}

/// Information about a top process.
#[derive(Debug, Serialize)]
struct TopProcessInfo {
    pid: String,
    registered_name: Option<String>,
    metric_value: u64,
    current_function: Option<String>,
}

/// Request for the get_memory_info tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetMemoryInfoRequest {
    /// The node name to query.
    #[schemars(description = "The node name to query")]
    pub node: String,
}

/// Response from the get_memory_info tool.
#[derive(Debug, Serialize)]
struct GetMemoryInfoResponse {
    node: String,
    memory: MemoryInfo,
}

/// Memory information breakdown.
#[derive(Debug, Serialize)]
struct MemoryInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    total: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    processes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    processes_used: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    atom: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    atom_used: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    binary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ets: Option<String>,
}

/// Request for the get_allocator_info tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetAllocatorInfoRequest {
    /// The node name to query.
    #[schemars(description = "The node name to query")]
    pub node: String,
}

/// Response from the get_allocator_info tool.
#[derive(Debug, Serialize)]
struct GetAllocatorInfoResponse {
    node: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    recon_available: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allocator_stats: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fragmentation: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fallback_memory: Option<MemoryInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

/// Request for the get_system_info tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetSystemInfoRequest {
    /// The node name to query.
    #[schemars(description = "The node name to query")]
    pub node: String,
}

/// Response from the get_system_info tool.
#[derive(Debug, Serialize)]
struct GetSystemInfoResponse {
    node: String,
    process_count: u64,
    process_limit: u64,
    process_usage_percent: f64,
    port_count: u64,
    port_limit: u64,
    port_usage_percent: f64,
    atom_count: u64,
    atom_limit: u64,
    atom_usage_percent: f64,
    ets_count: u64,
    schedulers: u64,
    run_queue: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    warnings: Option<Vec<String>>,
}

/// Request for the list_ets_tables tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListEtsTablesRequest {
    /// The node name to query.
    #[schemars(description = "The node name to query")]
    pub node: String,
}

/// Response from the list_ets_tables tool.
#[derive(Debug, Serialize)]
struct ListEtsTablesResponse {
    node: String,
    tables: Vec<EtsTableInfo>,
}

/// Information about an ETS table.
#[derive(Debug, Serialize)]
struct EtsTableInfo {
    name: String,
    id: String,
    size: u64,
    memory: String,
    owner: String,
    #[serde(rename = "type")]
    table_type: String,
    protection: String,
}

/// Request for the get_ets_table_info tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetEtsTableInfoRequest {
    /// The node name to query.
    #[schemars(description = "The node name to query")]
    pub node: String,
    /// The table name or ID.
    #[schemars(description = "The table name (atom) or ID (integer)")]
    pub table: String,
}

/// Response from the get_ets_table_info tool.
#[derive(Debug, Serialize)]
struct GetEtsTableInfoResponse {
    node: String,
    table: String,
    info: EtsTableDetailedInfo,
}

/// Detailed information about an ETS table.
#[derive(Debug, Serialize)]
struct EtsTableDetailedInfo {
    id: String,
    name: String,
    #[serde(rename = "type")]
    table_type: String,
    size: u64,
    memory: String,
    owner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    heir: Option<String>,
    protection: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    compressed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    read_concurrency: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    write_concurrency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decentralized_counters: Option<bool>,
    keypos: u64,
}

/// Request for the sample_ets_table tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SampleEtsTableRequest {
    /// The node name to query.
    #[schemars(description = "The node name to query")]
    pub node: String,
    /// The table name or ID.
    #[schemars(description = "The table name (atom) or ID (integer)")]
    pub table: String,
    /// Maximum number of entries to return (default: 10).
    #[schemars(description = "Maximum number of entries to return (default: 10)")]
    pub limit: Option<u64>,
}

/// Response from the sample_ets_table tool.
#[derive(Debug, Serialize)]
struct SampleEtsTableResponse {
    node: String,
    table: String,
    sample_size: usize,
    entries: Vec<serde_json::Value>,
}

/// Request for the get_scheduler_usage tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetSchedulerUsageRequest {
    /// The node name to query.
    #[schemars(description = "The node name to query")]
    pub node: String,
    /// Sample duration in milliseconds (default: 1000).
    #[schemars(description = "Sample duration in milliseconds (default: 1000)")]
    pub sample_ms: Option<u64>,
}

/// Response from the get_scheduler_usage tool.
#[derive(Debug, Serialize)]
struct GetSchedulerUsageResponse {
    node: String,
    sample_ms: u64,
    scheduler_usage: Vec<SchedulerUsageInfo>,
    average_usage: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    used_recon: bool,
}

/// Information about a single scheduler's utilisation.
#[derive(Debug, Serialize)]
struct SchedulerUsageInfo {
    scheduler_id: u64,
    usage_percent: f64,
}

/// Request for the get_process_stacktrace tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetProcessStacktraceRequest {
    /// The node name to query.
    #[schemars(description = "The node name to query")]
    pub node: String,
    /// The PID to get stacktrace for (formats: <0.123.0>, #PID<0.123.0>, or 0.123.0).
    #[schemars(
        description = "The PID to get stacktrace for (formats: <0.123.0>, #PID<0.123.0>, or 0.123.0)"
    )]
    pub pid: String,
}

/// Response from the get_process_stacktrace tool.
#[derive(Debug, Serialize)]
struct GetProcessStacktraceResponse {
    node: String,
    pid: String,
    stacktrace: Vec<StackFrame>,
}

/// A single stack frame.
#[derive(Debug, Serialize)]
struct StackFrame {
    module: String,
    function: String,
    arity: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<u32>,
}

/// Request for the get_gen_server_state tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetGenServerStateRequest {
    /// The node name to query.
    #[schemars(description = "The node name to query")]
    pub node: String,
    /// The PID or registered name of the process (formats: <0.123.0>, #PID<0.123.0>, 0.123.0, or atom).
    #[schemars(
        description = "The PID or registered name of the process (formats: <0.123.0>, #PID<0.123.0>, 0.123.0, or atom)"
    )]
    pub pid: String,
    /// Timeout in milliseconds (default 5000).
    #[schemars(description = "Timeout in milliseconds (default 5000)")]
    #[serde(default = "default_gen_server_timeout")]
    pub timeout_ms: u64,
}

/// Default timeout for gen_server operations.
fn default_gen_server_timeout() -> u64 {
    5000
}

/// Response from the get_gen_server_state tool.
#[derive(Debug, Serialize)]
struct GetGenServerStateResponse {
    node: String,
    pid: String,
    state: serde_json::Value,
}

/// Request for the get_gen_server_status tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetGenServerStatusRequest {
    /// The node name to query.
    #[schemars(description = "The node name to query")]
    pub node: String,
    /// The PID or registered name of the process (formats: <0.123.0>, #PID<0.123.0>, 0.123.0, or atom).
    #[schemars(
        description = "The PID or registered name of the process (formats: <0.123.0>, #PID<0.123.0>, 0.123.0, or atom)"
    )]
    pub pid: String,
    /// Timeout in milliseconds (default 5000).
    #[schemars(description = "Timeout in milliseconds (default 5000)")]
    #[serde(default = "default_gen_server_timeout")]
    pub timeout_ms: u64,
}

/// Response from the get_gen_server_status tool.
#[derive(Debug, Serialize)]
struct GetGenServerStatusResponse {
    node: String,
    pid: String,
    status: serde_json::Value,
}

/// Request for the start_trace tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct StartTraceRequest {
    /// The node name to trace.
    #[schemars(description = "The node name to trace")]
    pub node: String,
    /// The module to trace.
    #[schemars(description = "The module to trace")]
    pub module: String,
    /// Optional specific function name (omit for all functions).
    #[schemars(description = "Optional specific function name (omit for all functions)")]
    pub function: Option<String>,
    /// Optional function arity (omit for all arities).
    #[schemars(description = "Optional function arity (omit for all arities)")]
    pub arity: Option<u8>,
    /// Maximum number of traces to collect (required for safety).
    #[schemars(description = "Maximum number of traces to collect (required for safety)")]
    pub max_traces: usize,
    /// Duration to trace in milliseconds (default 10000, max 60000).
    #[schemars(description = "Duration to trace in milliseconds (default 10000, max 60000)")]
    pub duration_ms: Option<u64>,
}

/// Response from the start_trace tool.
#[derive(Debug, Serialize)]
struct StartTraceResponse {
    trace_id: String,
    node: String,
    module: String,
    function: Option<String>,
    arity: Option<u8>,
    max_traces: usize,
    duration_ms: u64,
    using_recon: bool,
    message: String,
}

/// Request for the stop_trace tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct StopTraceRequest {
    /// The node name where tracing should be stopped.
    #[schemars(description = "The node name where tracing should be stopped")]
    pub node: String,
    /// Optional trace ID to stop a specific trace (omit to stop all traces on the node).
    #[schemars(
        description = "Optional trace ID to stop a specific trace (omit to stop all traces on the node)"
    )]
    pub trace_id: Option<String>,
}

/// Response from the stop_trace tool.
#[derive(Debug, Serialize)]
struct StopTraceResponse {
    success: bool,
    node: String,
    trace_id: Option<String>,
    traces_collected: usize,
    message: String,
}

/// Request for the get_trace_results tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetTraceResultsRequest {
    /// The node name where tracing is active.
    #[schemars(description = "The node name where tracing is active")]
    pub node: String,
    /// The trace ID returned from start_trace.
    #[schemars(description = "The trace ID returned from start_trace")]
    pub trace_id: String,
    /// Optional limit on the number of trace events to return (default: all available).
    #[schemars(
        description = "Optional limit on the number of trace events to return (default: all available)"
    )]
    pub limit: Option<usize>,
}

/// Response from the get_trace_results tool.
#[derive(Debug, Serialize)]
struct GetTraceResultsResponse {
    node: String,
    trace_id: String,
    events: Vec<crate::trace::TraceEvent>,
    event_count: usize,
}

/// Request for the get_error_logger_events tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetErrorLoggerEventsRequest {
    /// The node name to retrieve error logger events from.
    #[schemars(description = "The node name to retrieve error logger events from")]
    pub node: String,
    /// Maximum number of events to return (default: 50).
    #[serde(default = "default_error_logger_limit")]
    #[schemars(description = "Maximum number of events to return (default: 50)")]
    pub limit: usize,
}

fn default_error_logger_limit() -> usize {
    50
}

/// Response from the get_error_logger_events tool.
#[derive(Debug, Serialize)]
struct GetErrorLoggerEventsResponse {
    node: String,
    events: Vec<LogEvent>,
    event_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

/// A log event from the error logger.
#[derive(Debug, Clone, Serialize)]
struct LogEvent {
    timestamp: String,
    level: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<String>,
}

#[tool_router]
impl ErlDistMcpServer {
    /// Creates a new MCP server instance.
    pub fn new(mode: FormatterMode, allow_eval: bool) -> Self {
        let state = Arc::new(ServerState::new(mode, allow_eval));
        Self {
            state,
            tool_router: Self::tool_router(),
        }
    }

    /// Returns a reference to the server state.
    pub fn state(&self) -> &ServerState {
        &self.state
    }

    async fn peer_creation(&self, node_name: &str) -> u32 {
        self.state()
            .connection_manager
            .get_peer_creation(node_name)
            .await
            .unwrap_or(0)
    }

    /// Ensure the log handler module is installed on the remote node.
    ///
    /// Returns `Ok(true)` if freshly installed, `Ok(false)` if already present,
    /// or `Err` if installation failed (e.g. Erlang-only node without Elixir).
    async fn ensure_log_handler(&self, node: &str) -> Result<bool, String> {
        use crate::rpc;

        let probe = rpc::rpc_call(
            &self.state().connection_manager,
            node,
            "Elixir.ErlDistMcp.LogHandler",
            "get_events",
            vec![eetf::Term::from(eetf::FixInteger::from(0))],
            None,
        )
        .await;

        if probe.is_ok() {
            return Ok(false);
        }

        let install = rpc::rpc_call(
            &self.state().connection_manager,
            node,
            "Elixir.Code",
            "eval_string",
            vec![rpc::binary_from_str(LOG_HANDLER_SOURCE)],
            Some(10_000),
        )
        .await;

        match install {
            Ok(_) => Ok(true),
            Err(e) => Err(format!(
                "Failed to install log handler (node may not have Elixir available): {}",
                e
            )),
        }
    }

    /// Connect to an Erlang node.
    ///
    /// Establishes a connection to the specified Erlang node using the
    /// distribution protocol. The cookie must match the target node's cookie.
    #[tool(
        name = "connect_node",
        description = "Connect to an Erlang/BEAM node. Requires the full node name (e.g., 'myapp@localhost') and the Erlang cookie for authentication."
    )]
    pub async fn tool_connect_node(
        &self,
        Parameters(request): Parameters<ConnectNodeRequest>,
    ) -> Result<CallToolResult, McpError> {
        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        if request.cookie.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: cookie cannot be empty",
            )]));
        }

        if !request.node.contains('@') {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Error: invalid node name '{}'. Expected format: 'name@host'",
                request.node
            ))]));
        }

        match self
            .state()
            .connection_manager
            .connect(&request.node, &request.cookie)
            .await
        {
            Ok(()) => {
                let response = ConnectNodeResponse {
                    success: true,
                    node: request.node.clone(),
                    message: format!("Successfully connected to {}", request.node),
                };
                let json = serde_json::to_string_pretty(&response)
                    .unwrap_or_else(|_| format!("Connected to {}", request.node));
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error: {}",
                e
            ))])),
        }
    }

    /// Disconnect from an Erlang node.
    ///
    /// Gracefully closes the connection to the specified node.
    #[tool(
        name = "disconnect_node",
        description = "Disconnect from a connected Erlang/BEAM node."
    )]
    pub async fn tool_disconnect_node(
        &self,
        Parameters(request): Parameters<DisconnectNodeRequest>,
    ) -> Result<CallToolResult, McpError> {
        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        match self
            .state()
            .connection_manager
            .disconnect(&request.node)
            .await
        {
            Ok(()) => {
                let response = DisconnectNodeResponse {
                    success: true,
                    message: format!("Successfully disconnected from {}", request.node),
                };
                let json = serde_json::to_string_pretty(&response)
                    .unwrap_or_else(|_| format!("Disconnected from {}", request.node));
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error: {}",
                e
            ))])),
        }
    }

    /// List all connected nodes.
    ///
    /// Returns information about all current node connections,
    /// including their status and connection time.
    #[tool(
        name = "list_nodes",
        description = "List all connected Erlang/BEAM nodes and their status."
    )]
    pub async fn tool_list_nodes(&self) -> Result<CallToolResult, McpError> {
        let statuses = self.state().connection_manager.list_connections().await;

        let nodes: Vec<NodeInfo> = statuses
            .into_iter()
            .map(|status| {
                let connected_at = if status.state == ConnectionState::Connected {
                    status.connected_at.map(|instant| {
                        let duration = instant.elapsed();
                        format_duration(duration)
                    })
                } else {
                    None
                };

                NodeInfo {
                    name: status.name,
                    status: status.state.to_string(),
                    connected_at,
                }
            })
            .collect();

        let response = ListNodesResponse { nodes };
        let json = serde_json::to_string_pretty(&response).unwrap_or_else(|_| "[]".to_string());
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Set the output format mode.
    ///
    /// Changes the output format for all subsequent tool responses.
    /// The mode determines which BEAM language syntax is used to display Erlang terms.
    #[tool(
        name = "set_mode",
        description = "Set the output format mode for displaying Erlang terms. Available modes: erlang, elixir, gleam, lfe."
    )]
    pub async fn tool_set_mode(
        &self,
        Parameters(request): Parameters<SetModeRequest>,
    ) -> Result<CallToolResult, McpError> {
        if request.mode.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: mode cannot be empty",
            )]));
        }

        match request.mode.parse::<FormatterMode>() {
            Ok(mode) => {
                self.state().set_mode(mode).await;
                let response = SetModeResponse {
                    success: true,
                    mode: mode.to_string(),
                    message: format!("Output format mode set to {}", mode),
                };
                let json = serde_json::to_string_pretty(&response)
                    .unwrap_or_else(|_| format!("Mode set to {}", mode));
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Error: {}",
                e
            ))])),
        }
    }

    /// List processes on a connected node.
    ///
    /// Retrieves information about running processes, sorted by memory usage.
    /// Returns the top N processes based on the limit parameter.
    #[tool(
        name = "list_processes",
        description = "List processes running on the node, sorted by memory usage (descending). Returns pid, registered_name, current_function, memory, reductions, and message_queue_len for each process."
    )]
    pub async fn tool_list_processes(
        &self,
        Parameters(request): Parameters<ListProcessesRequest>,
    ) -> Result<CallToolResult, McpError> {
        use crate::rpc;

        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        // Step 1: Get list of all PIDs via erlang:processes()
        let pids_result = rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "erlang",
            "processes",
            vec![],
            None,
        )
        .await;

        let pids_term = match pids_result {
            Ok(term) => term,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get process list from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        // Extract PIDs from the list
        let pids = match rpc::extract_list(&pids_term) {
            Some(elements) => elements,
            None => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "Error: unexpected response format from erlang:processes()",
                )]));
            }
        };

        // Step 2: Gather info for each PID
        let info_keys = rpc::list(vec![
            rpc::atom("registered_name"),
            rpc::atom("current_function"),
            rpc::atom("memory"),
            rpc::atom("reductions"),
            rpc::atom("message_queue_len"),
        ]);

        let mut process_infos = Vec::new();

        for pid_term in pids {
            // Call erlang:process_info(Pid, Keys)
            let info_result = rpc::rpc_call(
                &self.state().connection_manager,
                &request.node,
                "erlang",
                "process_info",
                vec![pid_term.clone(), info_keys.clone()],
                None,
            )
            .await;

            let info_term = match info_result {
                Ok(term) => term,
                Err(_) => continue, // Process may have died, skip it
            };

            // Process the info list
            let process_info = match parse_process_info(pid_term, &info_term) {
                Some(info) => info,
                None => continue,
            };

            process_infos.push(process_info);
        }

        // Step 3: Sort by memory descending
        process_infos.sort_by(|a, b| b.memory.cmp(&a.memory));

        // Step 4: Apply limit
        let total_count = process_infos.len();
        process_infos.truncate(request.limit);

        let response = ListProcessesResponse {
            node: request.node.clone(),
            processes: process_infos,
            total_count,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize process list".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Get detailed information about a specific process.
    ///
    /// Retrieves comprehensive process information including registered name,
    /// current function, memory usage, message queue, and more.
    #[tool(
        name = "get_process_info",
        description = "Get detailed information about a specific process by PID. Returns comprehensive process details including registered name, current function, memory, message queue, links, monitors, and more. PID can be in formats: <0.123.0>, #PID<0.123.0>, or 0.123.0"
    )]
    pub async fn tool_get_process_info(
        &self,
        Parameters(request): Parameters<GetProcessInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        use crate::rpc;

        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        // Parse the PID from the string
        let creation = self.peer_creation(&request.node).await;
        let pid_term = match parse_pid(&request.pid, &request.node, creation) {
            Some(pid) => pid,
            None => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: invalid PID format '{}'. Expected formats: <0.123.0>, #PID<0.123.0>, or 0.123.0",
                    request.pid
                ))]));
            }
        };

        // Define comprehensive list of keys to fetch
        let info_keys = rpc::list(vec![
            rpc::atom("registered_name"),
            rpc::atom("current_function"),
            rpc::atom("initial_call"),
            rpc::atom("status"),
            rpc::atom("message_queue_len"),
            rpc::atom("messages"),
            rpc::atom("links"),
            rpc::atom("dictionary"),
            rpc::atom("trap_exit"),
            rpc::atom("error_handler"),
            rpc::atom("priority"),
            rpc::atom("group_leader"),
            rpc::atom("total_heap_size"),
            rpc::atom("heap_size"),
            rpc::atom("stack_size"),
            rpc::atom("reductions"),
            rpc::atom("garbage_collection"),
            rpc::atom("suspending"),
            rpc::atom("current_stacktrace"),
            rpc::atom("memory"),
        ]);

        // Call erlang:process_info(Pid, Keys)
        let info_result = rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "erlang",
            "process_info",
            vec![pid_term, info_keys],
            None,
        )
        .await;

        let info_term = match info_result {
            Ok(term) => term,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get process info from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        // Check if the result is 'undefined' (process not found)
        if let eetf::Term::Atom(atom) = &info_term
            && atom.name == "undefined"
        {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Error: process {} not found on node '{}'",
                request.pid, request.node
            ))]));
        }

        // Convert the term to a formatter-aware JSON representation
        let formatter = self.state().formatter.read().await;
        let info_json = term_to_json(&info_term, &**formatter);

        let response = GetProcessInfoResponse {
            node: request.node.clone(),
            pid: request.pid.clone(),
            info: info_json,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize process info".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Get top processes by resource usage (memory, reductions, or message queue).
    ///
    /// First attempts to use recon:proc_count/2 if available, otherwise falls back
    /// to manual process listing and sorting.
    #[tool(
        name = "top_processes",
        description = "Find top processes by resource usage. Sorts by memory, reductions, or message_queue and returns the top N processes. Attempts to use recon:proc_count/2 if available, otherwise uses manual approach. Returns pid, registered_name, metric value, and current_function."
    )]
    pub async fn tool_top_processes(
        &self,
        Parameters(request): Parameters<TopProcessesRequest>,
    ) -> Result<CallToolResult, McpError> {
        use crate::rpc;

        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        // Validate sort_by parameter
        let sort_key = match request.sort_by.as_str() {
            "memory" => "memory",
            "reductions" => "reductions",
            "message_queue" => "message_queue_len",
            _ => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: invalid sort_by value '{}'. Expected: memory, reductions, or message_queue",
                    request.sort_by
                ))]));
            }
        };

        // First attempt: try recon:proc_count/2
        let recon_key = match request.sort_by.as_str() {
            "memory" => "memory",
            "reductions" => "reductions",
            "message_queue" => "message_queue_len",
            _ => unreachable!(), // Already validated above
        };

        let recon_result = rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "recon",
            "proc_count",
            vec![
                rpc::atom(recon_key),
                eetf::Term::from(eetf::FixInteger::from(request.limit as i32)),
            ],
            None,
        )
        .await;

        // Check if recon is available
        let use_fallback = match &recon_result {
            Err(crate::error::RpcError::BadRpc { reason, .. }) => {
                // Check if this is {undef, _} indicating recon is not available
                reason.contains("undef")
            }
            Err(_) => true, // Other errors, use fallback
            Ok(_) => false, // Success, use recon result
        };

        let top_processes = if use_fallback {
            // Fallback: manual approach
            self.get_top_processes_manual(&request.node, sort_key, request.limit)
                .await?
        } else {
            // Parse recon result
            match recon_result {
                Ok(term) => self.parse_recon_proc_count(&term, &request.node).await?,
                Err(e) => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Error: failed to get top processes from node '{}': {}",
                        request.node, e
                    ))]));
                }
            }
        };

        let response = TopProcessesResponse {
            node: request.node.clone(),
            sort_by: request.sort_by.clone(),
            processes: top_processes,
            used_recon: !use_fallback,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize top processes".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Manual fallback for getting top processes.
    async fn get_top_processes_manual(
        &self,
        node: &str,
        sort_key: &str,
        limit: usize,
    ) -> Result<Vec<TopProcessInfo>, McpError> {
        use crate::rpc;

        // Get list of all PIDs
        let pids_result = rpc::rpc_call(
            &self.state().connection_manager,
            node,
            "erlang",
            "processes",
            vec![],
            None,
        )
        .await;

        let pids_term = match pids_result {
            Ok(term) => term,
            Err(e) => {
                return Err(McpError::internal_error(
                    format!("Failed to get process list from node '{}': {}", node, e),
                    None,
                ));
            }
        };

        let pids = rpc::extract_list(&pids_term).ok_or_else(|| {
            McpError::internal_error("Unexpected response format from erlang:processes()", None)
        })?;

        // Gather info for each PID
        let info_keys = rpc::list(vec![
            rpc::atom("registered_name"),
            rpc::atom("current_function"),
            rpc::atom(sort_key),
        ]);

        let mut process_data = Vec::new();

        for pid_term in pids {
            let info_result = rpc::rpc_call(
                &self.state().connection_manager,
                node,
                "erlang",
                "process_info",
                vec![pid_term.clone(), info_keys.clone()],
                None,
            )
            .await;

            let info_term = match info_result {
                Ok(term) => term,
                Err(_) => continue, // Process died, skip
            };

            if let Some(top_info) = parse_top_process_info(pid_term, &info_term, sort_key) {
                process_data.push(top_info);
            }
        }

        // Sort by metric value descending
        process_data.sort_by(|a, b| b.metric_value.cmp(&a.metric_value));

        // Apply limit
        process_data.truncate(limit);

        Ok(process_data)
    }

    /// Parse recon:proc_count/2 result.
    async fn parse_recon_proc_count(
        &self,
        term: &eetf::Term,
        _node: &str,
    ) -> Result<Vec<TopProcessInfo>, McpError> {
        use crate::rpc;

        // recon:proc_count/2 returns a list of {Pid, Value, [{current_function, MFA} | ...]}
        let result_list = rpc::extract_list(term).ok_or_else(|| {
            McpError::internal_error("Unexpected response format from recon:proc_count/2", None)
        })?;

        let mut top_processes = Vec::new();

        for item in result_list {
            let tuple_elements = rpc::extract_tuple(item).ok_or_else(|| {
                McpError::internal_error("Expected tuple in recon:proc_count/2 result", None)
            })?;

            if tuple_elements.len() != 3 {
                continue;
            }

            // Extract PID
            let pid_str = match &tuple_elements[0] {
                eetf::Term::Pid(pid) => format_pid(pid),
                _ => continue,
            };

            // Extract metric value
            let metric_value = match &tuple_elements[1] {
                eetf::Term::FixInteger(i) => i.value.max(0) as u64,
                eetf::Term::BigInteger(i) => {
                    use std::convert::TryInto;
                    let result: Result<i64, _> = (&i.value).try_into();
                    result.unwrap_or(0).max(0) as u64
                }
                _ => continue,
            };

            // Extract info list (third element)
            let info_list = rpc::extract_list(&tuple_elements[2]);
            let mut registered_name: Option<String> = None;
            let mut current_function: Option<String> = None;

            if let Some(info_items) = info_list {
                for info_item in info_items {
                    if let Some(info_tuple) = rpc::extract_tuple(info_item)
                        && info_tuple.len() == 2
                        && let Some(key) = rpc::extract_atom(&info_tuple[0])
                    {
                        match key {
                            "registered_name" => {
                                if let Some(name) = rpc::extract_atom(&info_tuple[1]) {
                                    registered_name = Some(name.to_string());
                                }
                            }
                            "current_function" => {
                                current_function = format_mfa(&info_tuple[1]);
                            }
                            _ => {}
                        }
                    }
                }
            }

            top_processes.push(TopProcessInfo {
                pid: pid_str,
                registered_name,
                metric_value,
                current_function,
            });
        }

        Ok(top_processes)
    }

    /// Find processes by registered name or module.
    ///
    /// Searches for processes matching the specified criteria. At least one of
    /// name or module must be provided.
    #[tool(
        name = "find_process",
        description = "Search for processes by registered name (substring, case-insensitive) or by current function module (exact match). At least one of name or module must be provided. Returns pid, registered_name, current_function, and memory for matching processes."
    )]
    pub async fn tool_find_process(
        &self,
        Parameters(request): Parameters<FindProcessRequest>,
    ) -> Result<CallToolResult, McpError> {
        use crate::rpc;

        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        // Validate that at least one search criterion is provided
        if request.name.is_none() && request.module.is_none() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: at least one of 'name' or 'module' must be provided",
            )]));
        }

        // Get list of all PIDs
        let pids_result = rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "erlang",
            "processes",
            vec![],
            None,
        )
        .await;

        let pids_term = match pids_result {
            Ok(term) => term,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get process list from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        let pids = match rpc::extract_list(&pids_term) {
            Some(elements) => elements,
            None => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "Error: unexpected response format from erlang:processes()",
                )]));
            }
        };

        // Gather info for each PID
        let info_keys = rpc::list(vec![
            rpc::atom("registered_name"),
            rpc::atom("current_function"),
            rpc::atom("memory"),
        ]);

        let mut found_processes = Vec::new();

        // Prepare search criteria
        let name_search = request.name.as_ref().map(|n| n.to_lowercase());
        let module_search = request.module.as_ref();

        for pid_term in pids {
            let info_result = rpc::rpc_call(
                &self.state().connection_manager,
                &request.node,
                "erlang",
                "process_info",
                vec![pid_term.clone(), info_keys.clone()],
                None,
            )
            .await;

            let info_term = match info_result {
                Ok(term) => term,
                Err(_) => continue, // Process died, skip
            };

            // Parse process info
            let process_info = match parse_found_process_info(pid_term, &info_term) {
                Some(info) => info,
                None => continue,
            };

            // Apply filters
            let mut matches = true;

            // Filter by registered name (substring, case-insensitive)
            if let Some(ref name_pattern) = name_search {
                if let Some(ref registered_name) = process_info.registered_name {
                    if !registered_name.to_lowercase().contains(name_pattern) {
                        matches = false;
                    }
                } else {
                    matches = false;
                }
            }

            // Filter by module (exact match on module part of current_function)
            if let Some(module_pattern) = module_search {
                if let Some(ref current_function) = process_info.current_function {
                    // Extract module from "module:function/arity"
                    let module_from_mfa = current_function.split(':').next().unwrap_or("");
                    if module_from_mfa != module_pattern.as_str() {
                        matches = false;
                    }
                } else {
                    matches = false;
                }
            }

            if matches {
                found_processes.push(process_info);
            }
        }

        let total_found = found_processes.len();

        let response = FindProcessResponse {
            node: request.node.clone(),
            processes: found_processes,
            total_found,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize process search results".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Inspect a process's message queue.
    ///
    /// Retrieves the messages currently in a process's mailbox. Warning: this
    /// operation can be expensive on processes with large message queues.
    #[tool(
        name = "get_message_queue",
        description = "Inspect a process's message queue. Returns the queue length and up to the specified number of messages. Warning: this operation may be expensive if the process has a large message queue (>1000 messages)."
    )]
    pub async fn tool_get_message_queue(
        &self,
        Parameters(request): Parameters<GetMessageQueueRequest>,
    ) -> Result<CallToolResult, McpError> {
        use crate::rpc;

        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        if request.pid.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: PID cannot be empty",
            )]));
        }

        // Parse PID from string
        let creation = self.peer_creation(&request.node).await;
        let pid_term = match parse_pid(&request.pid, &request.node, creation) {
            Some(term) => term,
            None => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: invalid PID format '{}'. Expected format: <0.123.0>, #PID<0.123.0>, or 0.123.0",
                    request.pid
                ))]));
            }
        };

        // Call erlang:process_info(Pid, messages)
        let info_result = rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "erlang",
            "process_info",
            vec![pid_term, rpc::atom("messages")],
            None,
        )
        .await;

        let info_term = match info_result {
            Ok(term) => term,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get message queue from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        // Check if process not found
        if let eetf::Term::Atom(ref atom) = info_term
            && atom.name == "undefined"
        {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Error: process {} not found",
                request.pid
            ))]));
        }

        // Extract messages from {messages, [Msg1, Msg2, ...]} tuple
        let tuple_elements = match rpc::extract_tuple(&info_term) {
            Some(elements) if elements.len() == 2 => elements,
            _ => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "Error: unexpected response format from erlang:process_info/2",
                )]));
            }
        };

        // Verify first element is 'messages' atom
        if let Some(key) = rpc::extract_atom(&tuple_elements[0]) {
            if key != "messages" {
                return Ok(CallToolResult::error(vec![Content::text(
                    "Error: unexpected response format from erlang:process_info/2",
                )]));
            }
        } else {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: unexpected response format from erlang:process_info/2",
            )]));
        }

        // Extract message list
        let messages_list = match rpc::extract_list(&tuple_elements[1]) {
            Some(messages) => messages,
            None => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "Error: unexpected response format for messages list",
                )]));
            }
        };

        let queue_length = messages_list.len() as u64;

        // Format messages according to current mode
        let formatter = get_formatter(self.state().get_mode().await);
        let mut formatted_messages = Vec::new();

        let limit = request.limit.min(messages_list.len());
        for msg_term in messages_list.iter().take(limit) {
            let formatted = term_to_json(msg_term, &*formatter);
            formatted_messages.push(formatted);
        }

        // Add warning if queue is large
        let warning = if queue_length > 1000 {
            Some(format!(
                "Warning: This process has a large message queue ({} messages). This may indicate a backlog or bottleneck.",
                queue_length
            ))
        } else {
            None
        };

        let response = GetMessageQueueResponse {
            node: request.node.clone(),
            pid: request.pid.clone(),
            queue_length,
            messages: formatted_messages,
            warning,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize message queue".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// List running OTP applications on a connected node.
    ///
    /// Retrieves the list of running applications with their names, descriptions, and versions.
    #[tool(
        name = "list_applications",
        description = "List all running OTP applications on the node. Returns the application name, description, and version for each running application."
    )]
    pub async fn tool_list_applications(
        &self,
        Parameters(request): Parameters<ListApplicationsRequest>,
    ) -> Result<CallToolResult, McpError> {
        use crate::rpc;

        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        // Call application:which_applications()
        let apps_result = rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "application",
            "which_applications",
            vec![],
            None,
        )
        .await;

        let apps_term = match apps_result {
            Ok(term) => term,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get applications from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        // Extract application list - each element is {Name, Description, Version}
        let apps_list = match rpc::extract_list(&apps_term) {
            Some(elements) => elements,
            None => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "Error: unexpected response format from application:which_applications()",
                )]));
            }
        };

        let mut applications = Vec::new();

        for app_term in apps_list {
            if let Some(app_info) = parse_application_info(app_term) {
                applications.push(app_info);
            }
        }

        let response = ListApplicationsResponse {
            node: request.node.clone(),
            applications,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize application list".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Get detailed information about a specific OTP application.
    ///
    /// Retrieves comprehensive information about an application including its metadata
    /// (description, version, modules, etc.) and its environment configuration.
    #[tool(
        name = "get_application_info",
        description = "Get detailed information about a specific OTP application. Returns application metadata (description, version, modules) and environment configuration. Handles: application not found."
    )]
    pub async fn tool_get_application_info(
        &self,
        Parameters(request): Parameters<GetApplicationInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        use crate::rpc;

        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        if request.app.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: application name cannot be empty",
            )]));
        }

        // Convert app name to atom term
        let app_atom = eetf::Term::Atom(eetf::Atom {
            name: request.app.clone(),
        });

        // Call application:get_all_key(App)
        let metadata_result = rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "application",
            "get_all_key",
            vec![app_atom.clone()],
            None,
        )
        .await;

        let metadata_term = match metadata_result {
            Ok(term) => term,
            Err(e) => {
                // Check if it's an application not found error
                let error_msg = format!("{}", e);
                if error_msg.contains("not_loaded") || error_msg.contains("undefined") {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Error: application '{}' not found on node '{}'",
                        request.app, request.node
                    ))]));
                }
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get application metadata from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        // Call application:get_all_env(App)
        let env_result = rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "application",
            "get_all_env",
            vec![app_atom],
            None,
        )
        .await;

        let env_term = match env_result {
            Ok(term) => term,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get application environment from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        // Format the results using the current formatter
        let formatter = self.state().formatter.read().await;

        let metadata_json = term_to_json(&metadata_term, &**formatter);
        let env_json = term_to_json(&env_term, &**formatter);

        let response = GetApplicationInfoResponse {
            node: request.node.clone(),
            app: request.app.clone(),
            metadata: metadata_json,
            environment: env_json,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize application info".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Get the supervision tree starting from a supervisor.
    ///
    /// Recursively traverses the supervision tree starting from the specified supervisor,
    /// showing the hierarchy of supervisors and workers. Limits recursion to 10 levels.
    #[tool(
        name = "get_supervision_tree",
        description = "Get the supervision tree starting from a supervisor. Recursively expands the tree showing workers and child supervisors. Args: node, root (PID or registered name). Handles: supervisor not found, not a supervisor. Limits recursion to 10 levels with warning."
    )]
    pub async fn tool_get_supervision_tree(
        &self,
        Parameters(request): Parameters<GetSupervisionTreeRequest>,
    ) -> Result<CallToolResult, McpError> {
        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        if request.root.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: root supervisor cannot be empty",
            )]));
        }

        // Parse root - either a PID or a registered name (atom)
        let creation = self.peer_creation(&request.node).await;
        let root_term = if let Some(pid_term) = parse_pid(&request.root, &request.node, creation) {
            pid_term
        } else {
            // Assume it's a registered name (atom)
            eetf::Term::Atom(eetf::Atom {
                name: request.root.clone(),
            })
        };

        // Recursively build the supervision tree
        let mut warning = None;
        let tree = match build_supervision_tree(
            &self.state().connection_manager,
            &request.node,
            root_term,
            0,
            10,
            &mut warning,
            creation,
        )
        .await
        {
            Ok(tree) => tree,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get supervision tree from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        let response = GetSupervisionTreeResponse {
            node: request.node.clone(),
            root: request.root.clone(),
            tree,
            warning,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize supervision tree".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Get memory breakdown for a node.
    ///
    /// Returns memory usage statistics including total, processes, system, atom, binary, code, and ETS.
    #[tool(
        name = "get_memory_info",
        description = "Get memory breakdown for a node. Returns memory statistics for: total, processes, processes_used, system, atom, atom_used, binary, code, ets. Values are formatted as human-readable sizes (e.g., 123.4 MB). Args: node."
    )]
    pub async fn tool_get_memory_info(
        &self,
        Parameters(request): Parameters<GetMemoryInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        use crate::rpc;

        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        // Call erlang:memory()
        let memory_result = rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "erlang",
            "memory",
            vec![],
            None,
        )
        .await;

        let memory_term = match memory_result {
            Ok(term) => term,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get memory info from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        // Extract memory info - erlang:memory() returns a list of {Key, Value} tuples
        let memory_list = match rpc::extract_list(&memory_term) {
            Some(elements) => elements,
            None => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "Error: unexpected response format from erlang:memory()",
                )]));
            }
        };

        let mut memory_info = MemoryInfo {
            total: None,
            processes: None,
            processes_used: None,
            system: None,
            atom: None,
            atom_used: None,
            binary: None,
            code: None,
            ets: None,
        };

        // Parse the memory info
        for item in memory_list {
            let tuple_elements = match rpc::extract_tuple(item) {
                Some(elements) if elements.len() == 2 => elements,
                _ => continue,
            };

            let key = match rpc::extract_atom(&tuple_elements[0]) {
                Some(atom) => atom,
                None => continue,
            };

            let value = match &tuple_elements[1] {
                eetf::Term::FixInteger(i) => i.value as u64,
                eetf::Term::BigInteger(b) => {
                    use std::convert::TryInto;
                    let result: Result<i64, _> = (&b.value).try_into();
                    match result {
                        Ok(i) => i as u64,
                        Err(_) => continue,
                    }
                }
                _ => continue,
            };

            let human_readable = format_bytes(value);

            match key {
                "total" => memory_info.total = Some(human_readable),
                "processes" => memory_info.processes = Some(human_readable),
                "processes_used" => memory_info.processes_used = Some(human_readable),
                "system" => memory_info.system = Some(human_readable),
                "atom" => memory_info.atom = Some(human_readable),
                "atom_used" => memory_info.atom_used = Some(human_readable),
                "binary" => memory_info.binary = Some(human_readable),
                "code" => memory_info.code = Some(human_readable),
                "ets" => memory_info.ets = Some(human_readable),
                _ => {}
            }
        }

        let response = GetMemoryInfoResponse {
            node: request.node.clone(),
            memory: memory_info,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize memory info".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(
        description = "Get allocator statistics and fragmentation info from a node. Attempts to use recon_alloc if available, otherwise falls back to basic erlang:memory()."
    )]
    pub async fn tool_get_allocator_info(
        &self,
        Parameters(request): Parameters<GetAllocatorInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        use crate::rpc;

        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        // First try recon_alloc:memory(allocated)
        let recon_memory_result = rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "recon_alloc",
            "memory",
            vec![eetf::Term::Atom("allocated".into())],
            None,
        )
        .await;

        let recon_available = match &recon_memory_result {
            Ok(_) => true,
            Err(e) => {
                let error_msg = format!("{}", e);
                !error_msg.contains("undef")
            }
        };

        if recon_available {
            // Get allocated memory stats
            let allocated_term = match recon_memory_result {
                Ok(term) => term,
                Err(e) => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Error: failed to get allocator info from node '{}': {}",
                        request.node, e
                    ))]));
                }
            };

            // Get fragmentation info
            let fragmentation_result = rpc::rpc_call(
                &self.state().connection_manager,
                &request.node,
                "recon_alloc",
                "fragmentation",
                vec![eetf::Term::Atom("current".into())],
                None,
            )
            .await;

            let fragmentation_term = match fragmentation_result {
                Ok(term) => term,
                Err(e) => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Error: failed to get fragmentation info from node '{}': {}",
                        request.node, e
                    ))]));
                }
            };

            // Convert terms to JSON using the formatter
            let formatter = self.state().formatter.read().await;
            let allocator_stats = term_to_json(&allocated_term, &**formatter);
            let fragmentation = term_to_json(&fragmentation_term, &**formatter);

            let response = GetAllocatorInfoResponse {
                node: request.node.clone(),
                recon_available: Some(true),
                allocator_stats: Some(allocator_stats),
                fragmentation: Some(fragmentation),
                fallback_memory: None,
                note: None,
            };

            let json = serde_json::to_string_pretty(&response)
                .unwrap_or_else(|_| "Failed to serialize allocator info".to_string());

            Ok(CallToolResult::success(vec![Content::text(json)]))
        } else {
            // Fallback to basic erlang:memory()
            let memory_result = rpc::rpc_call(
                &self.state().connection_manager,
                &request.node,
                "erlang",
                "memory",
                vec![],
                None,
            )
            .await;

            let memory_term = match memory_result {
                Ok(term) => term,
                Err(e) => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Error: failed to get memory info from node '{}': {}",
                        request.node, e
                    ))]));
                }
            };

            // Extract memory info - same as get_memory_info
            let memory_list = match rpc::extract_list(&memory_term) {
                Some(elements) => elements,
                None => {
                    return Ok(CallToolResult::error(vec![Content::text(
                        "Error: unexpected response format from erlang:memory()",
                    )]));
                }
            };

            let mut memory_info = MemoryInfo {
                total: None,
                processes: None,
                processes_used: None,
                system: None,
                atom: None,
                atom_used: None,
                binary: None,
                code: None,
                ets: None,
            };

            for item in memory_list {
                let tuple_elements = match rpc::extract_tuple(item) {
                    Some(elements) if elements.len() == 2 => elements,
                    _ => continue,
                };

                let key = match rpc::extract_atom(&tuple_elements[0]) {
                    Some(atom) => atom,
                    None => continue,
                };

                let value = match &tuple_elements[1] {
                    eetf::Term::FixInteger(i) => i.value as u64,
                    eetf::Term::BigInteger(b) => {
                        use std::convert::TryInto;
                        let result: Result<i64, _> = (&b.value).try_into();
                        match result {
                            Ok(i) => i as u64,
                            Err(_) => continue,
                        }
                    }
                    _ => continue,
                };

                let human_readable = format_bytes(value);

                match key {
                    "total" => memory_info.total = Some(human_readable),
                    "processes" => memory_info.processes = Some(human_readable),
                    "processes_used" => memory_info.processes_used = Some(human_readable),
                    "system" => memory_info.system = Some(human_readable),
                    "atom" => memory_info.atom = Some(human_readable),
                    "atom_used" => memory_info.atom_used = Some(human_readable),
                    "binary" => memory_info.binary = Some(human_readable),
                    "code" => memory_info.code = Some(human_readable),
                    "ets" => memory_info.ets = Some(human_readable),
                    _ => {}
                }
            }

            let response = GetAllocatorInfoResponse {
                node: request.node.clone(),
                recon_available: Some(false),
                allocator_stats: None,
                fragmentation: None,
                fallback_memory: Some(memory_info),
                note: Some(
                    "recon library not available - showing basic erlang:memory() info".to_string(),
                ),
            };

            let json = serde_json::to_string_pretty(&response)
                .unwrap_or_else(|_| "Failed to serialize allocator info".to_string());

            Ok(CallToolResult::success(vec![Content::text(json)]))
        }
    }

    /// Get system limits and counts.
    ///
    /// Returns information about system limits (process limit, port limit, etc.)
    /// and current usage counts. Warns if any resource is above 80% of its limit.
    #[tool(
        name = "get_system_info",
        description = "Get system limits and resource usage. Returns process, port, and atom counts vs limits, scheduler info, and ETS table count. Warns if any resource exceeds 80% of its limit."
    )]
    pub async fn tool_get_system_info(
        &self,
        Parameters(request): Parameters<GetSystemInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        use crate::rpc;

        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        // Get process count and limit
        let process_count = match rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "erlang",
            "system_info",
            vec![eetf::Term::Atom("process_count".into())],
            None,
        )
        .await
        {
            Ok(term) => extract_integer(&term).unwrap_or(0),
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get process_count from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        let process_limit = match rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "erlang",
            "system_info",
            vec![eetf::Term::Atom("process_limit".into())],
            None,
        )
        .await
        {
            Ok(term) => extract_integer(&term).unwrap_or(0),
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get process_limit from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        // Get port count and limit
        let port_count = match rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "erlang",
            "system_info",
            vec![eetf::Term::Atom("port_count".into())],
            None,
        )
        .await
        {
            Ok(term) => extract_integer(&term).unwrap_or(0),
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get port_count from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        let port_limit = match rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "erlang",
            "system_info",
            vec![eetf::Term::Atom("port_limit".into())],
            None,
        )
        .await
        {
            Ok(term) => extract_integer(&term).unwrap_or(0),
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get port_limit from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        // Get atom count and limit
        let atom_count = match rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "erlang",
            "system_info",
            vec![eetf::Term::Atom("atom_count".into())],
            None,
        )
        .await
        {
            Ok(term) => extract_integer(&term).unwrap_or(0),
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get atom_count from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        let atom_limit = match rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "erlang",
            "system_info",
            vec![eetf::Term::Atom("atom_limit".into())],
            None,
        )
        .await
        {
            Ok(term) => extract_integer(&term).unwrap_or(0),
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get atom_limit from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        // Get scheduler count
        let schedulers = match rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "erlang",
            "system_info",
            vec![eetf::Term::Atom("schedulers".into())],
            None,
        )
        .await
        {
            Ok(term) => extract_integer(&term).unwrap_or(0),
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get schedulers from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        // Get run queue length
        let run_queue = match rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "erlang",
            "statistics",
            vec![eetf::Term::Atom("run_queue".into())],
            None,
        )
        .await
        {
            Ok(term) => extract_integer(&term).unwrap_or(0),
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get run_queue from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        // Get ETS table count
        let ets_all = match rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "ets",
            "all",
            vec![],
            None,
        )
        .await
        {
            Ok(term) => term,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get ETS tables from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        let ets_count = rpc::extract_list(&ets_all)
            .map(|list| list.len() as u64)
            .unwrap_or(0);

        // Calculate usage percentages
        let process_usage_percent = if process_limit > 0 {
            (process_count as f64 / process_limit as f64) * 100.0
        } else {
            0.0
        };

        let port_usage_percent = if port_limit > 0 {
            (port_count as f64 / port_limit as f64) * 100.0
        } else {
            0.0
        };

        let atom_usage_percent = if atom_limit > 0 {
            (atom_count as f64 / atom_limit as f64) * 100.0
        } else {
            0.0
        };

        // Generate warnings for resources above 80%
        let mut warnings = Vec::new();
        if process_usage_percent > 80.0 {
            warnings.push(format!(
                "Process usage at {:.1}% of limit ({}/{})",
                process_usage_percent, process_count, process_limit
            ));
        }
        if port_usage_percent > 80.0 {
            warnings.push(format!(
                "Port usage at {:.1}% of limit ({}/{})",
                port_usage_percent, port_count, port_limit
            ));
        }
        if atom_usage_percent > 80.0 {
            warnings.push(format!(
                "Atom usage at {:.1}% of limit ({}/{})",
                atom_usage_percent, atom_count, atom_limit
            ));
        }

        let response = GetSystemInfoResponse {
            node: request.node.clone(),
            process_count,
            process_limit,
            process_usage_percent,
            port_count,
            port_limit,
            port_usage_percent,
            atom_count,
            atom_limit,
            atom_usage_percent,
            ets_count,
            schedulers,
            run_queue,
            warnings: if warnings.is_empty() {
                None
            } else {
                Some(warnings)
            },
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize system info".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// List ETS tables on a node.
    ///
    /// Retrieves information about all ETS (Erlang Term Storage) tables on the specified node,
    /// including size, memory usage, owner, type, and protection level. Results are sorted
    /// by memory usage (descending) to help identify memory-intensive tables.
    #[tool(
        name = "list_ets_tables",
        description = "List all ETS tables on a node with their metadata (size, memory, owner, type, protection). Results are sorted by memory usage (descending)."
    )]
    pub async fn tool_list_ets_tables(
        &self,
        Parameters(request): Parameters<ListEtsTablesRequest>,
    ) -> Result<CallToolResult, McpError> {
        use crate::rpc;

        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        // Get list of all ETS table references
        let ets_all = match rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "ets",
            "all",
            vec![],
            None,
        )
        .await
        {
            Ok(term) => term,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get ETS tables from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        let table_refs = match rpc::extract_list(&ets_all) {
            Some(list) => list,
            None => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "Error: unexpected response format from ets:all()",
                )]));
            }
        };

        // Get info for each table
        let mut tables = Vec::new();
        for table_ref in table_refs {
            // Call ets:info(Table)
            let info_result = rpc::rpc_call(
                &self.state().connection_manager,
                &request.node,
                "ets",
                "info",
                vec![table_ref.clone()],
                None,
            )
            .await;

            let info_term = match info_result {
                Ok(term) => term,
                Err(_) => continue, // Skip tables that we can't get info for
            };

            // Parse the info list
            if let Some(table_info) = parse_ets_table_info(&info_term) {
                tables.push(table_info);
            }
        }

        // Sort by memory descending
        tables.sort_by(|a, b| {
            // Extract numeric value from memory string for comparison
            let a_bytes = parse_memory_bytes(&a.memory);
            let b_bytes = parse_memory_bytes(&b.memory);
            b_bytes.cmp(&a_bytes)
        });

        let response = ListEtsTablesResponse {
            node: request.node.clone(),
            tables,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize ETS tables".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Get detailed information about a specific ETS table.
    ///
    /// Retrieves comprehensive metadata about an ETS table including its ID, name, type,
    /// size, memory usage, owner, heir, protection level, compression status, concurrency
    /// settings, and key position.
    #[tool(
        name = "get_ets_table_info",
        description = "Get detailed information about a specific ETS table by name or ID, including metadata like type, size, memory, owner, heir, protection, compression, and concurrency settings."
    )]
    pub async fn tool_get_ets_table_info(
        &self,
        Parameters(request): Parameters<GetEtsTableInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        use crate::rpc;

        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        if request.table.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: table name/ID cannot be empty",
            )]));
        }

        // Try to parse as integer ID first, otherwise treat as atom name
        let table_term = if let Ok(table_id) = request.table.parse::<i32>() {
            eetf::Term::from(eetf::FixInteger::from(table_id))
        } else {
            eetf::Term::Atom(eetf::Atom::from(request.table.as_str()))
        };

        // Call ets:info(Table)
        let info_term = match rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "ets",
            "info",
            vec![table_term],
            None,
        )
        .await
        {
            Ok(term) => term,
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("badarg") {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Error: table '{}' not found on node '{}'",
                        request.table, request.node
                    ))]));
                }
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get table info from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        // Check for undefined response (table doesn't exist)
        if let eetf::Term::Atom(a) = &info_term
            && a.name == "undefined"
        {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Error: table '{}' not found on node '{}'",
                request.table, request.node
            ))]));
        }

        // Parse the detailed info
        let info = match parse_ets_table_detailed_info(&info_term) {
            Some(info) => info,
            None => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "Error: unexpected response format from ets:info/1",
                )]));
            }
        };

        let response = GetEtsTableInfoResponse {
            node: request.node.clone(),
            table: request.table.clone(),
            info,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize ETS table info".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Sample entries from an ETS table.
    ///
    /// **Warning**: This operation may be slow on large tables.
    #[tool(
        name = "sample_ets_table",
        description = "Sample entries from an ETS table. Warning: This operation may be slow on large tables and may fail on protected tables. Use with caution on production systems."
    )]
    pub async fn tool_sample_ets_table(
        &self,
        Parameters(request): Parameters<SampleEtsTableRequest>,
    ) -> Result<CallToolResult, McpError> {
        use crate::rpc;

        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        if request.table.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: table name/ID cannot be empty",
            )]));
        }

        let limit = request.limit.unwrap_or(10);

        // Try to parse as integer ID first, otherwise treat as atom name
        let table_term = if let Ok(table_id) = request.table.parse::<i32>() {
            eetf::Term::from(eetf::FixInteger::from(table_id))
        } else {
            eetf::Term::Atom(eetf::Atom::from(request.table.as_str()))
        };

        // Call ets:match(Table, '$1', Limit)
        // This returns {[Match], Continuation} or '$end_of_table' when done
        let match_term = match rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "ets",
            "match",
            vec![
                table_term,
                eetf::Term::Atom(eetf::Atom::from("$1")),
                eetf::Term::from(eetf::FixInteger::from(limit as i32)),
            ],
            None,
        )
        .await
        {
            Ok(term) => term,
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("badarg") {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Error: table '{}' not found on node '{}'",
                        request.table, request.node
                    ))]));
                }
                if error_msg.contains("protected") || error_msg.contains("private") {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Error: table '{}' is protected and cannot be sampled",
                        request.table
                    ))]));
                }
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to sample table on node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        // Check for '$end_of_table' response (empty table)
        if let eetf::Term::Atom(a) = &match_term
            && a.name == "$end_of_table"
        {
            let response = SampleEtsTableResponse {
                node: request.node.clone(),
                table: request.table.clone(),
                sample_size: 0,
                entries: vec![],
            };

            let json = serde_json::to_string_pretty(&response)
                .unwrap_or_else(|_| "Failed to serialize ETS table sample".to_string());

            return Ok(CallToolResult::success(vec![Content::text(json)]));
        }

        // Parse the match response: {[Match1, Match2, ...], Continuation}
        let tuple_elements = match rpc::extract_tuple(&match_term) {
            Some(elements) if elements.len() == 2 => elements,
            _ => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "Error: unexpected response format from ets:match/3",
                )]));
            }
        };

        // Extract the matches list
        let matches_list = match rpc::extract_list(&tuple_elements[0]) {
            Some(list) => list,
            None => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "Error: unexpected response format from ets:match/3 - expected list",
                )]));
            }
        };

        // Format each entry using the current formatter
        let formatter = self.state().formatter.read().await;
        let mut entries = Vec::new();

        for match_term in matches_list {
            // Each match is wrapped in a list with one element (the matched term)
            if let Some(match_elements) = rpc::extract_list(match_term)
                && let Some(entry_term) = match_elements.first()
            {
                let formatted = term_to_json(entry_term, &**formatter);
                entries.push(formatted);
            }
        }

        let response = SampleEtsTableResponse {
            node: request.node.clone(),
            table: request.table.clone(),
            sample_size: entries.len(),
            entries,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize ETS table sample".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Get scheduler utilisation statistics.
    ///
    /// Shows CPU usage for each scheduler over a sampling period. First attempts to use
    /// recon:scheduler_usage/1 if available, otherwise falls back to manual calculation
    /// using erlang:statistics(scheduler_wall_time).
    ///
    /// **Note**: Scheduler wall time must be enabled first with
    /// `erlang:system_flag(scheduler_wall_time, true)`. The fallback method will
    /// automatically enable it if needed.
    #[tool(
        name = "get_scheduler_usage",
        description = "Get scheduler utilisation statistics showing CPU usage per scheduler. First attempts to use recon:scheduler_usage/1, then falls back to erlang:statistics(scheduler_wall_time). Note: Wall time tracking must be enabled first."
    )]
    pub async fn tool_get_scheduler_usage(
        &self,
        Parameters(request): Parameters<GetSchedulerUsageRequest>,
    ) -> Result<CallToolResult, McpError> {
        use crate::rpc;

        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        let sample_ms = request.sample_ms.unwrap_or(1000);

        // First attempt: Try recon:scheduler_usage/1
        let recon_result = rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "recon",
            "scheduler_usage",
            vec![eetf::Term::from(eetf::FixInteger::from(sample_ms as i32))],
            Some(sample_ms + 5000), // Allow extra time for sampling
        )
        .await;

        match recon_result {
            Ok(recon_term) => {
                // Parse recon output: list of {SchedulerId, Usage} tuples
                let usage_list = parse_recon_scheduler_usage(&recon_term)?;

                let average_usage = if usage_list.is_empty() {
                    0.0
                } else {
                    usage_list.iter().map(|s| s.usage_percent).sum::<f64>()
                        / usage_list.len() as f64
                };

                let response = GetSchedulerUsageResponse {
                    node: request.node.clone(),
                    sample_ms,
                    scheduler_usage: usage_list,
                    average_usage,
                    note: None,
                    used_recon: true,
                };

                let json = serde_json::to_string_pretty(&response)
                    .unwrap_or_else(|_| "Failed to serialize scheduler usage".to_string());

                return Ok(CallToolResult::success(vec![Content::text(json)]));
            }
            Err(_) => {
                // recon unavailable or failed, fall through to manual method
            }
        }

        // Fallback: Manual calculation using erlang:statistics(scheduler_wall_time)
        // First, ensure scheduler_wall_time is enabled
        let enable_result = rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "erlang",
            "system_flag",
            vec![
                eetf::Term::Atom(eetf::Atom::from("scheduler_wall_time")),
                eetf::Term::Atom(eetf::Atom::from("true")),
            ],
            None,
        )
        .await;

        if let Err(e) = enable_result {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Error: failed to enable scheduler_wall_time on node '{}': {}",
                request.node, e
            ))]));
        }

        // Get initial wall time measurements
        let initial_term = rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "erlang",
            "statistics",
            vec![eetf::Term::Atom(eetf::Atom::from("scheduler_wall_time"))],
            None,
        )
        .await
        .map_err(|e| {
            McpError::internal_error(
                format!(
                    "Failed to get initial scheduler_wall_time on node '{}': {}",
                    request.node, e
                ),
                None,
            )
        })?;

        // Sleep for the sampling duration
        tokio::time::sleep(tokio::time::Duration::from_millis(sample_ms)).await;

        // Get final wall time measurements
        let final_term = rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "erlang",
            "statistics",
            vec![eetf::Term::Atom(eetf::Atom::from("scheduler_wall_time"))],
            None,
        )
        .await
        .map_err(|e| {
            McpError::internal_error(
                format!(
                    "Failed to get final scheduler_wall_time on node '{}': {}",
                    request.node, e
                ),
                None,
            )
        })?;

        // Calculate utilisation
        let usage_list = calculate_scheduler_usage(&initial_term, &final_term)?;

        let average_usage = if usage_list.is_empty() {
            0.0
        } else {
            usage_list.iter().map(|s| s.usage_percent).sum::<f64>() / usage_list.len() as f64
        };

        let response = GetSchedulerUsageResponse {
            node: request.node.clone(),
            sample_ms,
            scheduler_usage: usage_list,
            average_usage,
            note: Some(
                "Calculated using erlang:statistics(scheduler_wall_time). Scheduler wall time was automatically enabled.".to_string(),
            ),
            used_recon: false,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize scheduler usage".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Get the stacktrace for a specific process.
    ///
    /// This tool calls `erlang:process_info(Pid, current_stacktrace)` to retrieve
    /// the current call stack of a process. Useful for debugging stuck or long-running processes.
    #[tool(
        name = "get_process_stacktrace",
        description = "Get the current stack trace of a process, showing where it is currently executing. Useful for debugging stuck or long-running processes."
    )]
    pub async fn tool_get_process_stacktrace(
        &self,
        Parameters(request): Parameters<GetProcessStacktraceRequest>,
    ) -> Result<CallToolResult, McpError> {
        use crate::rpc;

        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        if request.pid.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: pid cannot be empty",
            )]));
        }

        // Parse PID from string
        let creation = self.peer_creation(&request.node).await;
        let pid_term = parse_pid(&request.pid, &request.node, creation).ok_or_else(|| {
            McpError::internal_error(
                format!(
                    "Invalid PID format '{}'. Expected formats: <0.123.0>, #PID<0.123.0>, or 0.123.0",
                    request.pid
                ),
                None,
            )
        })?;

        // RPC call to erlang:process_info(Pid, current_stacktrace)
        let term = rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "erlang",
            "process_info",
            vec![
                pid_term,
                eetf::Term::Atom(eetf::Atom::from("current_stacktrace")),
            ],
            None,
        )
        .await
        .map_err(|e| {
            McpError::internal_error(
                format!(
                    "Failed to get stacktrace for PID '{}' on node '{}': {}",
                    request.pid, request.node, e
                ),
                None,
            )
        })?;

        // Check for undefined (process not found)
        if let eetf::Term::Atom(a) = &term
            && a.name == "undefined"
        {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Error: process '{}' not found on node '{}'",
                request.pid, request.node
            ))]));
        }

        // Parse stacktrace response: {current_stacktrace, [Frame1, Frame2, ...]}
        let tuple_elements = rpc::extract_tuple(&term).ok_or_else(|| {
            McpError::internal_error(
                "Unexpected response format from erlang:process_info/2 - expected tuple",
                None,
            )
        })?;

        if tuple_elements.len() != 2 {
            return Err(McpError::internal_error(
                format!(
                    "Unexpected tuple length {} from erlang:process_info/2 - expected 2",
                    tuple_elements.len()
                ),
                None,
            ));
        }

        // Verify first element is 'current_stacktrace' atom
        if let eetf::Term::Atom(a) = &tuple_elements[0] {
            if a.name != "current_stacktrace" {
                return Err(McpError::internal_error(
                    format!(
                        "Unexpected key '{}' from erlang:process_info/2 - expected 'current_stacktrace'",
                        a.name
                    ),
                    None,
                ));
            }
        } else {
            return Err(McpError::internal_error(
                "Unexpected first element in process_info tuple - expected atom",
                None,
            ));
        }

        // Extract stacktrace list
        let stacktrace_list = rpc::extract_list(&tuple_elements[1]).ok_or_else(|| {
            McpError::internal_error(
                "Unexpected stacktrace format from erlang:process_info/2 - expected list",
                None,
            )
        })?;

        // Parse stack frames
        let formatter = self.state().formatter.read().await;
        let stacktrace = parse_stacktrace(stacktrace_list, &**formatter)?;

        let response = GetProcessStacktraceResponse {
            node: request.node.clone(),
            pid: request.pid.clone(),
            stacktrace,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize stacktrace".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Get the internal state of a gen_server process.
    ///
    /// This tool calls `sys:get_state/2` to retrieve the internal state of an OTP
    /// process (gen_server, gen_statem, gen_event, etc.). Useful for debugging server internals.
    ///
    /// Warning: This operation may block if the process is busy handling a call.
    #[tool(
        name = "get_gen_server_state",
        description = "Get the internal state of a gen_server or other OTP process using sys:get_state/2. Warning: This may block if the process is busy."
    )]
    pub async fn tool_get_gen_server_state(
        &self,
        Parameters(request): Parameters<GetGenServerStateRequest>,
    ) -> Result<CallToolResult, McpError> {
        use crate::rpc;

        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        if request.pid.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: pid cannot be empty",
            )]));
        }

        // Parse PID or registered name from string
        // Try parsing as PID first, fall back to atom (registered name)
        let creation = self.peer_creation(&request.node).await;
        let pid_or_name_term =
            parse_pid(&request.pid, &request.node, creation).unwrap_or_else(|| {
                // Treat as registered name (atom)
                eetf::Term::Atom(eetf::Atom::from(request.pid.as_str()))
            });

        // RPC call to sys:get_state(PidOrName, Timeout)
        let timeout_term = eetf::Term::from(eetf::FixInteger::from(request.timeout_ms as i32));

        let term = rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "sys",
            "get_state",
            vec![pid_or_name_term, timeout_term],
            Some(request.timeout_ms + 1000),
        )
        .await
        .map_err(|e| {
            let error_msg = format!("{}", e);

            // Check for common errors
            if error_msg.contains("timeout") {
                McpError::internal_error(
                    format!(
                        "Timeout waiting for state from process '{}' on node '{}'. The process may be busy.",
                        request.pid, request.node
                    ),
                    None,
                )
            } else if error_msg.contains("noproc") {
                McpError::internal_error(
                    format!(
                        "Process '{}' not found on node '{}'",
                        request.pid, request.node
                    ),
                    None,
                )
            } else if error_msg.contains("not_a_gen_server") || error_msg.contains("undef") {
                McpError::internal_error(
                    format!(
                        "Process '{}' on node '{}' is not a gen_server or does not support sys:get_state/2",
                        request.pid, request.node
                    ),
                    None,
                )
            } else {
                McpError::internal_error(
                    format!(
                        "Failed to get state for process '{}' on node '{}': {}",
                        request.pid, request.node, e
                    ),
                    None,
                )
            }
        })?;

        // Format the state using term_to_json
        let formatter = self.state().formatter.read().await;
        let state_json = term_to_json(&term, &**formatter);

        let response = GetGenServerStateResponse {
            node: request.node.clone(),
            pid: request.pid.clone(),
            state: state_json,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize gen_server state".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Get the full status of a gen_server or other OTP process.
    ///
    /// This tool calls `sys:get_status/2` to retrieve the full status information
    /// of an OTP process, including status, parent, modules, logged events, and state.
    ///
    /// Warning: This operation may block if the process is busy handling a call.
    #[tool(
        name = "get_gen_server_status",
        description = "Get the full status of a gen_server or other OTP process using sys:get_status/2. Returns status, parent, modules, logged events, and state. Warning: This may block if the process is busy."
    )]
    pub async fn tool_get_gen_server_status(
        &self,
        Parameters(request): Parameters<GetGenServerStatusRequest>,
    ) -> Result<CallToolResult, McpError> {
        use crate::rpc;

        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        if request.pid.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: pid cannot be empty",
            )]));
        }

        // Parse PID or registered name from string
        // Try parsing as PID first, fall back to atom (registered name)
        let creation = self.peer_creation(&request.node).await;
        let pid_or_name_term =
            parse_pid(&request.pid, &request.node, creation).unwrap_or_else(|| {
                // Treat as registered name (atom)
                eetf::Term::Atom(eetf::Atom::from(request.pid.as_str()))
            });

        // RPC call to sys:get_status(PidOrName, Timeout)
        let timeout_term = eetf::Term::from(eetf::FixInteger::from(request.timeout_ms as i32));

        let term = rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "sys",
            "get_status",
            vec![pid_or_name_term, timeout_term],
            Some(request.timeout_ms + 1000),
        )
        .await
        .map_err(|e| {
            let error_msg = format!("{}", e);

            // Check for common errors
            if error_msg.contains("timeout") {
                McpError::internal_error(
                    format!(
                        "Timeout waiting for status from process '{}' on node '{}'. The process may be busy.",
                        request.pid, request.node
                    ),
                    None,
                )
            } else if error_msg.contains("noproc") {
                McpError::internal_error(
                    format!(
                        "Process '{}' not found on node '{}'",
                        request.pid, request.node
                    ),
                    None,
                )
            } else if error_msg.contains("not_an_otp_process") || error_msg.contains("undef") {
                McpError::internal_error(
                    format!(
                        "Process '{}' on node '{}' is not an OTP process or does not support sys:get_status/2",
                        request.pid, request.node
                    ),
                    None,
                )
            } else {
                McpError::internal_error(
                    format!(
                        "Failed to get status for process '{}' on node '{}': {}",
                        request.pid, request.node, e
                    ),
                    None,
                )
            }
        })?;

        // Format the status using term_to_json
        let formatter = self.state().formatter.read().await;
        let status_json = term_to_json(&term, &**formatter);

        let response = GetGenServerStatusResponse {
            node: request.node.clone(),
            pid: request.pid.clone(),
            status: status_json,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize gen_server status".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Start tracing function calls on a node.
    ///
    /// WARNING: Tracing can have significant performance impact in production environments.
    /// Use max_traces and duration_ms parameters to limit the scope. Default duration is 10 seconds.
    ///
    /// This tool first attempts to use recon_trace (if available) for production-safe tracing with
    /// automatic rate limiting. If recon is not available, it falls back to dbg with manual safeguards.
    ///
    /// Parameters:
    /// - node: The target node name
    /// - module: The module to trace
    /// - function: Optional specific function name (omit for all functions)
    /// - arity: Optional function arity (omit for all arities)
    /// - max_traces: Maximum number of traces to collect (required for safety)
    /// - duration_ms: Duration to trace in milliseconds (default: 10000, max: 60000)
    #[tool(
        name = "start_trace",
        description = "Start tracing function calls on an Erlang node. WARNING: Can impact performance in production. Collects traces for specified module/function. First tries recon_trace (if available) for production-safe tracing, falls back to dbg. Use max_traces and duration_ms to limit scope (default: 10s, max: 60s)."
    )]
    pub async fn tool_start_trace(
        &self,
        Parameters(request): Parameters<StartTraceRequest>,
    ) -> Result<CallToolResult, McpError> {
        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        if request.module.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: module name cannot be empty",
            )]));
        }

        // Validate duration (cap at 60 seconds for safety)
        let duration_ms = request.duration_ms.unwrap_or(10000).min(60000);

        // Build trace parameters
        let params = TraceParams {
            node: &request.node,
            module: &request.module,
            function: request.function.as_deref(),
            arity: request.arity,
            max_traces: request.max_traces,
            duration_ms,
        };

        // Start the trace
        let trace_id = self
            .state()
            .trace_manager
            .start_trace(&self.state().connection_manager, params)
            .await
            .map_err(|e| {
                McpError::internal_error(
                    format!("Failed to start trace on node '{}': {}", request.node, e),
                    None,
                )
            })?;

        // Check if recon was used
        let session = self.state().trace_manager.get_session(&trace_id).await;
        let using_recon = session.map(|s| s.using_recon).unwrap_or(false);

        let response = StartTraceResponse {
            trace_id: trace_id.clone(),
            node: request.node.clone(),
            module: request.module.clone(),
            function: request.function.clone(),
            arity: request.arity,
            max_traces: request.max_traces,
            duration_ms,
            using_recon,
            message: format!(
                "Trace started with ID '{}'. Tracing will automatically stop after {}ms. Use get_trace_results to retrieve traces.",
                trace_id, duration_ms
            ),
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize trace start response".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Stop tracing function calls on an Erlang node.
    ///
    /// Parameters:
    /// - node: The node name where tracing should be stopped
    /// - trace_id: Optional trace ID to stop a specific trace (omit to stop all traces on the node)
    #[tool(
        name = "stop_trace",
        description = "Stop tracing function calls on an Erlang node. If trace_id is provided, stops that specific trace session. If trace_id is omitted, stops all trace sessions on the node. Returns the number of traces collected before stopping."
    )]
    pub async fn tool_stop_trace(
        &self,
        Parameters(request): Parameters<StopTraceRequest>,
    ) -> Result<CallToolResult, McpError> {
        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        // Stop the trace(s)
        let traces_collected = self
            .state()
            .trace_manager
            .stop_trace(
                &self.state().connection_manager,
                &request.node,
                request.trace_id.as_deref(),
            )
            .await
            .map_err(|e| {
                McpError::internal_error(
                    format!("Failed to stop trace on node '{}': {}", request.node, e),
                    None,
                )
            })?;

        let message = if let Some(ref trace_id) = request.trace_id {
            format!(
                "Trace session '{}' stopped. {} traces were collected.",
                trace_id, traces_collected
            )
        } else {
            format!(
                "All trace sessions on node '{}' stopped. {} total traces were collected.",
                request.node, traces_collected
            )
        };

        let response = StopTraceResponse {
            success: true,
            node: request.node.clone(),
            trace_id: request.trace_id.clone(),
            traces_collected,
            message,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize stop trace response".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Retrieve trace output from an active trace session.
    ///
    /// Parameters:
    /// - node: The node name where tracing is active
    /// - trace_id: The trace ID returned from start_trace
    /// - limit: Optional limit on the number of trace events to return
    #[tool(
        name = "get_trace_results",
        description = "Retrieve trace output from an active trace session. Returns a list of trace events (calls, returns, exceptions) captured since the last retrieval. Note: Only works with dbg-based traces (fallback), not recon_trace."
    )]
    pub async fn tool_get_trace_results(
        &self,
        Parameters(request): Parameters<GetTraceResultsRequest>,
    ) -> Result<CallToolResult, McpError> {
        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        if request.trace_id.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: trace_id cannot be empty",
            )]));
        }

        // Get the formatter
        let formatter = self.state().formatter.read().await;

        // Retrieve trace results
        let events = self
            .state()
            .trace_manager
            .get_trace_results(&request.trace_id, request.limit, &**formatter)
            .await
            .map_err(|e| {
                McpError::internal_error(
                    format!(
                        "Failed to get trace results for trace '{}': {}",
                        request.trace_id, e
                    ),
                    None,
                )
            })?;

        let event_count = events.len();

        let response = GetTraceResultsResponse {
            node: request.node.clone(),
            trace_id: request.trace_id.clone(),
            events,
            event_count,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize trace results response".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Get recent error logger events from a node.
    ///
    /// Auto-installs a lightweight log handler on the remote node (Elixir nodes only)
    /// that captures events in an ETS ring buffer.
    #[tool(
        name = "get_error_logger_events",
        description = "Get recent error logger events from a node. Auto-installs a lightweight log handler that captures events in an ETS ring buffer. Returns timestamp, level, message, and metadata for each event. Requires Elixir to be available on the target node."
    )]
    pub async fn tool_get_error_logger_events(
        &self,
        Parameters(request): Parameters<GetErrorLoggerEventsRequest>,
    ) -> Result<CallToolResult, McpError> {
        use crate::rpc;

        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        let freshly_installed = match self.ensure_log_handler(&request.node).await {
            Ok(fresh) => fresh,
            Err(e) => {
                let response = GetErrorLoggerEventsResponse {
                    node: request.node.clone(),
                    events: vec![],
                    event_count: 0,
                    note: Some(format!(
                        "Log handler not available: {}. \
                         This tool requires Elixir to be available on the target node.",
                        e
                    )),
                };
                let json = serde_json::to_string_pretty(&response).unwrap_or_else(|_| {
                    "Failed to serialize error logger events response".to_string()
                });
                return Ok(CallToolResult::success(vec![Content::text(json)]));
            }
        };

        let events_result = rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "Elixir.ErlDistMcp.LogHandler",
            "get_events",
            vec![eetf::Term::from(eetf::FixInteger::from(
                request.limit as i32,
            ))],
            None,
        )
        .await;

        let mut events = Vec::new();
        let mut note: Option<String> = None;

        match events_result {
            Ok(term) => {
                if let Some(event_list) = rpc::extract_list(&term) {
                    for event_term in event_list {
                        if let Some(event) = parse_log_event(event_term) {
                            events.push(event);
                        }
                    }
                }

                if freshly_installed {
                    note = Some(
                        "Log handler installed. Events will be captured from now on.".to_string(),
                    );
                }
            }
            Err(e) => {
                note = Some(format!("Failed to retrieve log events: {}", e));
            }
        }

        let event_count = events.len();

        let response = GetErrorLoggerEventsResponse {
            node: request.node.clone(),
            events,
            event_count,
            note,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize error logger events response".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}

/// Parse a log event from a term.
fn parse_log_event(term: &eetf::Term) -> Option<LogEvent> {
    use crate::rpc;

    // Log events can have various formats. Common format is a map with:
    // #{time => Timestamp, level => Level, msg => Message, meta => Metadata}
    if let eetf::Term::Map(event_map) = term {
        let mut timestamp: Option<String> = None;
        let mut level: Option<String> = None;
        let mut message: Option<String> = None;
        let mut metadata: Option<String> = None;

        for (key, value) in &event_map.map {
            if let eetf::Term::Atom(key_atom) = key {
                match key_atom.name.as_str() {
                    "time" | "timestamp" | "ts" => {
                        timestamp = Some(format_log_timestamp(value));
                    }
                    "level" | "severity" => {
                        level = Some(extract_atom_or_string(value));
                    }
                    "msg" | "message" | "report" => {
                        message = Some(format_log_message(value));
                    }
                    "meta" | "metadata" => {
                        metadata = Some(format_log_metadata(value));
                    }
                    _ => {}
                }
            }
        }

        Some(LogEvent {
            timestamp: timestamp.unwrap_or_else(|| "unknown".to_string()),
            level: level.unwrap_or_else(|| "info".to_string()),
            message: message.unwrap_or_default(),
            metadata,
        })
    } else if let Some(tuple_elements) = rpc::extract_tuple(term) {
        // Alternative tuple format: {Level, Time, Message} or similar
        if tuple_elements.len() >= 3 {
            let level = extract_atom_or_string(&tuple_elements[0]);
            let timestamp = format_log_timestamp(&tuple_elements[1]);
            let message = format_log_message(&tuple_elements[2]);

            Some(LogEvent {
                timestamp,
                level,
                message,
                metadata: None,
            })
        } else {
            None
        }
    } else {
        None
    }
}

/// Format a log timestamp from various term formats.
fn format_log_timestamp(term: &eetf::Term) -> String {
    use crate::rpc;

    match term {
        // Integer timestamp (milliseconds since epoch)
        eetf::Term::FixInteger(i) => {
            let secs = i.value as i64 / 1000;
            if let Some(dt) = chrono::DateTime::from_timestamp(secs, 0) {
                dt.format("%Y-%m-%d %H:%M:%S").to_string()
            } else {
                format!("{}", i.value)
            }
        }
        eetf::Term::BigInteger(b) => {
            let result: Result<i64, _> = (&b.value).try_into();
            if let Ok(value) = result {
                // OTP logger uses microseconds; detect based on magnitude.
                // Values > 10^13 are microseconds, otherwise milliseconds.
                let (secs, nanos) = if value > 10_000_000_000_000 {
                    (value / 1_000_000, ((value % 1_000_000) * 1000) as u32)
                } else {
                    (value / 1000, ((value % 1000) * 1_000_000) as u32)
                };
                if let Some(dt) = chrono::DateTime::from_timestamp(secs, nanos) {
                    return dt.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
                }
            }
            format!("{:?}", b.value)
        }
        // Tuple format: {MegaSecs, Secs, MicroSecs}
        _ => {
            if let Some(tuple_elements) = rpc::extract_tuple(term)
                && tuple_elements.len() == 3
                && let (Some(mega), Some(secs), Some(_micro)) = (
                    extract_integer(&tuple_elements[0]),
                    extract_integer(&tuple_elements[1]),
                    extract_integer(&tuple_elements[2]),
                )
            {
                let total_secs = mega * 1_000_000 + secs;
                if let Some(dt) = chrono::DateTime::from_timestamp(total_secs as i64, 0) {
                    return dt.format("%Y-%m-%d %H:%M:%S").to_string();
                }
            }
            format!("{:?}", term)
        }
    }
}

/// Format a log message from various term formats.
fn format_log_message(term: &eetf::Term) -> String {
    match term {
        eetf::Term::Binary(b) => String::from_utf8_lossy(&b.bytes).to_string(),
        eetf::Term::List(_) => {
            // Could be a charlist
            if let Some(s) = extract_string(term) {
                s
            } else {
                format!("{:?}", term)
            }
        }
        eetf::Term::Atom(a) => a.name.clone(),
        _ => format!("{:?}", term),
    }
}

/// Format log metadata from a map term into a readable string.
fn format_log_metadata(term: &eetf::Term) -> String {
    if let eetf::Term::Map(map) = term {
        let pairs: Vec<String> = map
            .map
            .iter()
            .filter_map(|(key, value)| {
                let k = extract_atom_or_string(key);
                let v = extract_atom_or_string(value);
                if v == "nil" {
                    None
                } else {
                    Some(format!("{}: {}", k, v))
                }
            })
            .collect();
        pairs.join(", ")
    } else {
        extract_atom_or_string(term)
    }
}

/// Extract an atom or string from a term.
fn extract_atom_or_string(term: &eetf::Term) -> String {
    match term {
        eetf::Term::Atom(a) => a.name.clone(),
        eetf::Term::Binary(b) => String::from_utf8_lossy(&b.bytes).to_string(),
        eetf::Term::List(_) => {
            if let Some(s) = extract_string(term) {
                s
            } else {
                format!("{:?}", term)
            }
        }
        _ => format!("{:?}", term),
    }
}

// ============================================================================
// RPC Call Tool
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct RpcCallRequest {
    node: String,
    module: String,
    function: String,
    args: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct RpcCallResponse {
    node: String,
    module: String,
    function: String,
    result: serde_json::Value,
}

// ============================================================================
// Eval Code Tool
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct EvalCodeRequest {
    node: String,
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    bindings: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct EvalCodeResponse {
    node: String,
    code: String,
    result: serde_json::Value,
}

/// Request for the get_module_info tool.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct GetModuleInfoRequest {
    /// The node name to query.
    #[schemars(description = "The node name to query")]
    node: String,
    /// The module name to inspect.
    #[schemars(description = "The module name (atom, e.g. 'lists', 'gen_server')")]
    module: String,
}

/// Response from the get_module_info tool.
#[derive(Debug, Serialize)]
struct GetModuleInfoResponse {
    node: String,
    module: String,
    exports: serde_json::Value,
    attributes: serde_json::Value,
    compile: serde_json::Value,
    md5: serde_json::Value,
}

/// Request for the list_module_functions tool.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct ListModuleFunctionsRequest {
    /// The node name to query.
    #[schemars(description = "The node name to query")]
    node: String,
    /// The module name to inspect.
    #[schemars(description = "The module name (atom, e.g. 'lists', 'gen_server')")]
    module: String,
}

/// Response from the list_module_functions tool.
#[derive(Debug, Serialize)]
struct ListModuleFunctionsResponse {
    node: String,
    module: String,
    functions: Vec<FunctionExport>,
}

/// A function export with name and arity.
#[derive(Debug, Serialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FunctionExport {
    function: String,
    arity: u32,
}

impl ErlDistMcpServer {
    /// Make an arbitrary RPC call to an Erlang node.
    ///
    /// WARNING: This tool is potentially dangerous and requires the --allow-eval flag.
    /// Only use this when you understand the security implications.
    ///
    /// # Arguments
    /// * `node` - The node name to call
    /// * `module` - The module name (atom)
    /// * `function` - The function name (atom)
    /// * `args` - JSON array of arguments
    ///
    /// # JSON to Term Conversion
    /// - string -> binary
    /// - integer -> integer
    /// - float -> float
    /// - bool -> atom (true/false)
    /// - null -> nil
    /// - array -> list
    /// - object -> map
    /// - {"__atom__": "name"} -> atom
    /// - {"__pid__": "<0.123.0>"} -> pid
    ///
    /// # Example
    /// ```json
    /// {
    ///   "node": "node@localhost",
    ///   "module": "erlang",
    ///   "function": "node",
    ///   "args": []
    /// }
    /// ```
    #[tool(
        name = "rpc_call",
        description = "Make an arbitrary RPC call to an Erlang node (requires --allow-eval flag)"
    )]
    pub async fn tool_rpc_call(&self, request: RpcCallRequest) -> Result<CallToolResult, McpError> {
        // Check if eval is allowed
        if !self.state().allow_eval {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: rpc_call tool requires --allow-eval flag to be set. \
                This tool can execute arbitrary code on connected nodes and should \
                only be used when you trust the caller and understand the security implications."
                    .to_string(),
            )]));
        }

        // Convert JSON args to Erlang terms
        let creation = self.peer_creation(&request.node).await;
        let term_args: Result<Vec<eetf::Term>, String> = request
            .args
            .iter()
            .map(|v| json_to_term(v, &request.node, creation))
            .collect();

        let term_args = match term_args {
            Ok(args) => args,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to convert arguments to Erlang terms: {}",
                    e
                ))]));
            }
        };

        // Make the RPC call
        let result = match crate::rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            &request.module,
            &request.function,
            term_args,
            None,
        )
        .await
        {
            Ok(term) => term,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: RPC call failed: {}",
                    e
                ))]));
            }
        };

        // Format the result using the current formatter
        let formatter = self.state().formatter.read().await;
        let result_json = term_to_json(&result, &**formatter);

        let response = RpcCallResponse {
            node: request.node.clone(),
            module: request.module.clone(),
            function: request.function.clone(),
            result: result_json,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize RPC result".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Evaluate Erlang expressions on a remote node.
    ///
    /// WARNING: This tool is potentially dangerous and requires the --allow-eval flag.
    /// Only use this when you understand the security implications.
    ///
    /// The evaluation runs in a sandboxed process with:
    /// - Timeout (default 5 seconds)
    /// - Heap size limit (default 10MB)
    /// - Low priority
    /// - Function call whitelist (arithmetic, list/map operations, type checks)
    ///
    /// # Arguments
    /// * `node` - The node name to evaluate on
    /// * `code` - The Erlang expression to evaluate (must end with '.')
    /// * `bindings` - Optional JSON object with variable bindings
    ///
    /// # Bindings Conversion
    /// Variable names are atoms. Values follow same rules as rpc_call args.
    ///
    /// # Example
    /// ```json
    /// {
    ///   "node": "node@localhost",
    ///   "code": "X + Y.",
    ///   "bindings": {"X": 10, "Y": 20}
    /// }
    /// ```
    #[tool(
        name = "eval_code",
        description = "Evaluate Erlang expressions on a remote node (requires --allow-eval flag)"
    )]
    pub async fn tool_eval_code(
        &self,
        request: EvalCodeRequest,
    ) -> Result<CallToolResult, McpError> {
        // Check if eval is allowed
        if !self.state().allow_eval {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: eval_code tool requires --allow-eval flag to be set. \
                This tool can execute arbitrary code on connected nodes and should \
                only be used when you trust the caller and understand the security implications."
                    .to_string(),
            )]));
        }

        // Ensure code ends with period
        let code = if request.code.trim().ends_with('.') {
            request.code.clone()
        } else {
            format!("{}.", request.code.trim())
        };

        // Convert bindings from JSON to Erlang map
        let bindings = if let Some(ref bindings_obj) = request.bindings {
            match bindings_obj {
                serde_json::Value::Object(obj) => {
                    let mut map_entries = Vec::new();
                    for (var_name, value) in obj {
                        // Variable names must be atoms
                        let var_atom = crate::rpc::atom(var_name);
                        let creation = self.peer_creation(&request.node).await;
                        let term_value = match json_to_term(value, &request.node, creation) {
                            Ok(t) => t,
                            Err(e) => {
                                return Ok(CallToolResult::error(vec![Content::text(format!(
                                    "Error: failed to convert binding '{}' to Erlang term: {}",
                                    var_name, e
                                ))]));
                            }
                        };
                        map_entries.push((var_atom, term_value));
                    }
                    crate::rpc::map(map_entries)
                }
                _ => {
                    return Ok(CallToolResult::error(vec![Content::text(
                        "Error: bindings must be a JSON object".to_string(),
                    )]));
                }
            }
        } else {
            // Empty map for no bindings
            crate::rpc::map(Vec::new())
        };

        // Build options map for eval helper (timeout, max_heap_size)
        let opts = crate::rpc::map(vec![
            (
                crate::rpc::atom("timeout"),
                eetf::Term::from(eetf::FixInteger::from(5000)),
            ),
            (
                crate::rpc::atom("max_heap_size"),
                eetf::Term::from(eetf::FixInteger::from(10000000)),
            ),
        ]);

        // Check if helper module is loaded on the target node
        let helper_module = "mcp_eval_helper";
        let check_result = crate::rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            "code",
            "which",
            vec![crate::rpc::atom(helper_module)],
            None,
        )
        .await;

        // If module not loaded, return an error with instructions
        match check_result {
            Ok(eetf::Term::Atom(atom)) if atom.name == "non_existing" => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "Error: mcp_eval_helper module not loaded on target node.\n\n\
                    To use eval_code, you must first compile and load the helper module on the target node:\n\n\
                    1. Copy erlang/mcp_eval_helper.erl to the target node\n\
                    2. Compile: c(mcp_eval_helper)\n\
                    3. Or add it to your application's code path\n\n\
                    The helper module provides sandboxed evaluation with:\n\
                    - Function call whitelisting\n\
                    - Heap size limits\n\
                    - Timeout protection"
                        .to_string(),
                )]));
            }
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to check if helper module is loaded: {}",
                    e
                ))]));
            }
            Ok(_) => {
                // Module is loaded, continue
            }
        }

        // Call the eval helper
        let eval_result = crate::rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            helper_module,
            "eval",
            vec![crate::rpc::binary_from_str(&code), bindings, opts],
            Some(10000), // 10 second timeout for the RPC call itself
        )
        .await;

        let result = match eval_result {
            Ok(term) => term,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: eval RPC failed: {}",
                    e
                ))]));
            }
        };

        // Parse the result: {ok, Value} | {error, {parse_error, Reason}} | {error, {eval_error, Reason}}
        if let Some(tuple_elements) = crate::rpc::extract_tuple(&result)
            && tuple_elements.len() == 2
            && let eetf::Term::Atom(ref status_atom) = tuple_elements[0]
        {
            match status_atom.name.as_str() {
                "ok" => {
                    // Success - format and return the value
                    let formatter = self.state().formatter.read().await;
                    let result_json = term_to_json(&tuple_elements[1], &**formatter);

                    let response = EvalCodeResponse {
                        node: request.node.clone(),
                        code: code.clone(),
                        result: result_json,
                    };

                    let json = serde_json::to_string_pretty(&response)
                        .unwrap_or_else(|_| "Failed to serialize eval result".to_string());

                    return Ok(CallToolResult::success(vec![Content::text(json)]));
                }
                "error" => {
                    // Error - parse and format the error
                    let formatter = self.state().formatter.read().await;
                    let error_json = term_to_json(&tuple_elements[1], &**formatter);

                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Evaluation failed:\n{}",
                        serde_json::to_string_pretty(&error_json)
                            .unwrap_or_else(|_| format!("{:?}", tuple_elements[1]))
                    ))]));
                }
                _ => {}
            }
        }

        Ok(CallToolResult::error(vec![Content::text(format!(
            "Error: unexpected result format from eval helper: {:?}",
            result
        ))]))
    }

    /// Get metadata information about a loaded module.
    ///
    /// This tool retrieves comprehensive information about a module including its
    /// exports, attributes, compile information, and MD5 checksum. Does NOT require
    /// the --allow-eval flag as it's read-only.
    #[tool(
        name = "get_module_info",
        description = "Get metadata for a loaded module including exports, attributes, compile info, and MD5. Args: node, module. Handles: module not loaded. Read-only, does not require --allow-eval."
    )]
    pub async fn tool_get_module_info(
        &self,
        Parameters(request): Parameters<GetModuleInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        use crate::rpc;

        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        if request.module.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: module name cannot be empty",
            )]));
        }

        // Call Module:module_info() which is equivalent to calling erlang:get_module_info(Module)
        // We'll call it as Module:module_info() directly
        let info_result = rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            &request.module,
            "module_info",
            vec![],
            None,
        )
        .await;

        let info_term = match info_result {
            Ok(term) => term,
            Err(e) => {
                // Check if it's a module not loaded error
                let error_msg = format!("{}", e);
                if error_msg.contains("undef") || error_msg.contains("not loaded") {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Error: module '{}' not loaded on node '{}'",
                        request.module, request.node
                    ))]));
                }
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get module info from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        // module_info() returns a list of {Key, Value} tuples
        // Keys we care about: module, exports, attributes, compile, md5
        let info_list = match rpc::extract_list(&info_term) {
            Some(list) => list,
            None => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: unexpected module_info format (expected list): {:?}",
                    info_term
                ))]));
            }
        };

        // Extract specific keys from the info list
        let mut exports_term = None;
        let mut attributes_term = None;
        let mut compile_term = None;
        let mut md5_term = None;

        for item in info_list {
            if let Some(tuple) = rpc::extract_tuple(item)
                && tuple.len() == 2
                && let eetf::Term::Atom(ref key) = tuple[0]
            {
                match key.name.as_str() {
                    "exports" => exports_term = Some(&tuple[1]),
                    "attributes" => attributes_term = Some(&tuple[1]),
                    "compile" => compile_term = Some(&tuple[1]),
                    "md5" => md5_term = Some(&tuple[1]),
                    _ => {}
                }
            }
        }

        // Format the results using the current formatter
        let formatter = self.state().formatter.read().await;

        let exports_json = exports_term
            .map(|t| term_to_json(t, &**formatter))
            .unwrap_or(serde_json::Value::Null);
        let attributes_json = attributes_term
            .map(|t| term_to_json(t, &**formatter))
            .unwrap_or(serde_json::Value::Null);
        let compile_json = compile_term
            .map(|t| term_to_json(t, &**formatter))
            .unwrap_or(serde_json::Value::Null);
        let md5_json = md5_term
            .map(|t| term_to_json(t, &**formatter))
            .unwrap_or(serde_json::Value::Null);

        let response = GetModuleInfoResponse {
            node: request.node.clone(),
            module: request.module.clone(),
            exports: exports_json,
            attributes: attributes_json,
            compile: compile_json,
            md5: md5_json,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize module info".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// List all exported functions from a module.
    ///
    /// This tool retrieves the list of exported functions (public API) from a module,
    /// returning function names and their arities sorted alphabetically. Does NOT require
    /// the --allow-eval flag as it's read-only.
    #[tool(
        name = "list_module_functions",
        description = "List all exported functions from a module. Returns list of {function, arity} pairs sorted alphabetically. Args: node, module. Handles: module not loaded. Read-only, does not require --allow-eval."
    )]
    pub async fn tool_list_module_functions(
        &self,
        Parameters(request): Parameters<ListModuleFunctionsRequest>,
    ) -> Result<CallToolResult, McpError> {
        use crate::rpc;

        if request.node.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: node name cannot be empty",
            )]));
        }

        if request.module.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Error: module name cannot be empty",
            )]));
        }

        // Call Module:module_info(exports) to get just the exports list
        let exports_result = rpc::rpc_call(
            &self.state().connection_manager,
            &request.node,
            &request.module,
            "module_info",
            vec![rpc::atom("exports")],
            None,
        )
        .await;

        let exports_term = match exports_result {
            Ok(term) => term,
            Err(e) => {
                // Check if it's a module not loaded error
                let error_msg = format!("{}", e);
                if error_msg.contains("undef") || error_msg.contains("not loaded") {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Error: module '{}' not loaded on node '{}'",
                        request.module, request.node
                    ))]));
                }
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: failed to get module exports from node '{}': {}",
                    request.node, e
                ))]));
            }
        };

        // module_info(exports) returns a list of {Function, Arity} tuples
        let exports_list = match rpc::extract_list(&exports_term) {
            Some(list) => list,
            None => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: unexpected exports format (expected list): {:?}",
                    exports_term
                ))]));
            }
        };

        // Parse each {Function, Arity} tuple
        let mut functions = Vec::new();
        for item in exports_list {
            if let Some(tuple) = rpc::extract_tuple(item)
                && tuple.len() == 2
                && let eetf::Term::Atom(ref func_atom) = tuple[0]
            {
                let arity = match &tuple[1] {
                    eetf::Term::FixInteger(i) => i.value as u32,
                    _ => continue,
                };

                functions.push(FunctionExport {
                    function: func_atom.name.clone(),
                    arity,
                });
            }
        }

        // Sort alphabetically by function name, then by arity
        functions.sort();

        let response = ListModuleFunctionsResponse {
            node: request.node.clone(),
            module: request.module.clone(),
            functions,
        };

        let json = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| "Failed to serialize module functions".to_string());

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}

/// Convert JSON value to Erlang term.
///
/// # Conversion Rules
/// - string -> binary
/// - integer -> integer
/// - float -> float
/// - bool -> atom (true/false)
/// - null -> nil
/// - array -> list
/// - object -> map (or special types)
/// - {"__atom__": "name"} -> atom
/// - {"__pid__": "<0.123.0>"} -> pid
fn json_to_term(
    value: &serde_json::Value,
    node_name: &str,
    creation: u32,
) -> Result<eetf::Term, String> {
    use crate::rpc;

    match value {
        serde_json::Value::Null => Ok(rpc::nil()),
        serde_json::Value::Bool(b) => Ok(rpc::atom(if *b { "true" } else { "false" })),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if i >= i32::MIN as i64 && i <= i32::MAX as i64 {
                    Ok(eetf::Term::from(eetf::FixInteger::from(i as i32)))
                } else {
                    Ok(eetf::Term::from(eetf::BigInteger::from(i)))
                }
            } else if let Some(f) = n.as_f64() {
                Ok(eetf::Term::from(eetf::Float { value: f }))
            } else {
                Err("number too large".to_string())
            }
        }
        serde_json::Value::String(s) => Ok(rpc::binary_from_str(s)),
        serde_json::Value::Array(arr) => {
            let terms: Result<Vec<eetf::Term>, String> = arr
                .iter()
                .map(|v| json_to_term(v, node_name, creation))
                .collect();
            Ok(rpc::list(terms?))
        }
        serde_json::Value::Object(obj) => {
            // Check for special types
            if let Some(atom_name) = obj.get("__atom__") {
                if let serde_json::Value::String(name) = atom_name {
                    return Ok(rpc::atom(name));
                }
                return Err("__atom__ value must be a string".to_string());
            }

            if let Some(pid_str) = obj.get("__pid__") {
                if let serde_json::Value::String(pid) = pid_str {
                    return parse_pid(pid, node_name, creation)
                        .ok_or_else(|| format!("invalid PID format: {}", pid));
                }
                return Err("__pid__ value must be a string".to_string());
            }

            // Regular map
            let entries: Result<Vec<(eetf::Term, eetf::Term)>, String> = obj
                .iter()
                .map(|(k, v)| {
                    Ok((
                        rpc::binary_from_str(k),
                        json_to_term(v, node_name, creation)?,
                    ))
                })
                .collect();
            Ok(rpc::map(entries?))
        }
    }
}

/// Parse recon:scheduler_usage/1 output.
fn parse_recon_scheduler_usage(term: &eetf::Term) -> Result<Vec<SchedulerUsageInfo>, McpError> {
    use crate::rpc;

    // recon:scheduler_usage/1 returns a list of {SchedulerId, Usage} tuples
    let usage_list = rpc::extract_list(term).ok_or_else(|| {
        McpError::internal_error(
            "Unexpected response format from recon:scheduler_usage/1 - expected list",
            None,
        )
    })?;

    let mut result = Vec::new();

    for entry in usage_list {
        let tuple_elements = rpc::extract_tuple(entry).ok_or_else(|| {
            McpError::internal_error(
                "Unexpected element in recon:scheduler_usage/1 response - expected tuple",
                None,
            )
        })?;

        if tuple_elements.len() != 2 {
            continue;
        }

        let scheduler_id = extract_integer(&tuple_elements[0]).ok_or_else(|| {
            McpError::internal_error(
                "Failed to extract scheduler ID from recon:scheduler_usage/1 response",
                None,
            )
        })?;

        let usage_percent = if let eetf::Term::Float(f) = &tuple_elements[1] {
            f.value * 100.0 // recon returns 0.0-1.0, convert to percentage
        } else if let Some(int_val) = extract_integer(&tuple_elements[1]) {
            int_val as f64 * 100.0
        } else {
            return Err(McpError::internal_error(
                "Failed to extract usage from recon:scheduler_usage/1 response",
                None,
            ));
        };

        result.push(SchedulerUsageInfo {
            scheduler_id,
            usage_percent,
        });
    }

    Ok(result)
}

/// Calculate scheduler usage from wall time statistics.
fn calculate_scheduler_usage(
    initial: &eetf::Term,
    final_term: &eetf::Term,
) -> Result<Vec<SchedulerUsageInfo>, McpError> {
    use crate::rpc;

    // erlang:statistics(scheduler_wall_time) returns either:
    // - [{SchedulerId, ActiveTime, TotalTime}, ...] when enabled
    // - the atom 'undefined' when not available
    if matches!(initial, eetf::Term::Atom(a) if a.name == "undefined") {
        return Err(McpError::internal_error(
            "scheduler_wall_time is not available on this node (statistics returned 'undefined')",
            None,
        ));
    }
    if matches!(final_term, eetf::Term::Atom(a) if a.name == "undefined") {
        return Err(McpError::internal_error(
            "scheduler_wall_time became unavailable between measurements",
            None,
        ));
    }

    let initial_list = rpc::extract_list(initial).ok_or_else(|| {
        McpError::internal_error(
            format!(
                "Unexpected response format from erlang:statistics(scheduler_wall_time) - expected list, got: {:?}",
                std::mem::discriminant(initial)
            ),
            None,
        )
    })?;

    let final_list = rpc::extract_list(final_term).ok_or_else(|| {
        McpError::internal_error(
            format!(
                "Unexpected response format from erlang:statistics(scheduler_wall_time) - expected list, got: {:?}",
                std::mem::discriminant(final_term)
            ),
            None,
        )
    })?;

    if initial_list.len() != final_list.len() {
        return Err(McpError::internal_error(
            "Scheduler count changed between measurements",
            None,
        ));
    }

    let mut result = Vec::new();

    for (initial_entry, final_entry) in initial_list.iter().zip(final_list.iter()) {
        let initial_tuple = rpc::extract_tuple(initial_entry).ok_or_else(|| {
            McpError::internal_error(
                "Unexpected element in scheduler_wall_time response - expected tuple",
                None,
            )
        })?;

        let final_tuple = rpc::extract_tuple(final_entry).ok_or_else(|| {
            McpError::internal_error(
                "Unexpected element in scheduler_wall_time response - expected tuple",
                None,
            )
        })?;

        if initial_tuple.len() != 3 || final_tuple.len() != 3 {
            continue;
        }

        let scheduler_id = extract_integer(&initial_tuple[0])
            .ok_or_else(|| McpError::internal_error("Failed to extract scheduler ID", None))?;

        let initial_active = extract_integer(&initial_tuple[1]).ok_or_else(|| {
            McpError::internal_error("Failed to extract initial active time", None)
        })?;

        let initial_total = extract_integer(&initial_tuple[2]).ok_or_else(|| {
            McpError::internal_error("Failed to extract initial total time", None)
        })?;

        let final_active = extract_integer(&final_tuple[1])
            .ok_or_else(|| McpError::internal_error("Failed to extract final active time", None))?;

        let final_total = extract_integer(&final_tuple[2])
            .ok_or_else(|| McpError::internal_error("Failed to extract final total time", None))?;

        // Calculate delta
        let active_delta = final_active.saturating_sub(initial_active);
        let total_delta = final_total.saturating_sub(initial_total);

        let usage_percent = if total_delta > 0 {
            (active_delta as f64 / total_delta as f64) * 100.0
        } else {
            0.0
        };

        result.push(SchedulerUsageInfo {
            scheduler_id,
            usage_percent,
        });
    }

    Ok(result)
}

/// Parse a stacktrace list from erlang:process_info(Pid, current_stacktrace).
///
/// Each frame can be either:
/// - {Module, Function, Arity, Location} tuple (with file/line info)
/// - {Module, Function, Arity} tuple (without location info)
fn parse_stacktrace(
    stacktrace_list: &[eetf::Term],
    _formatter: &dyn TermFormatter,
) -> Result<Vec<StackFrame>, McpError> {
    use crate::rpc;

    let mut result = Vec::new();

    for frame_term in stacktrace_list {
        let tuple_elements = rpc::extract_tuple(frame_term).ok_or_else(|| {
            McpError::internal_error("Unexpected stacktrace frame format - expected tuple", None)
        })?;

        if tuple_elements.len() < 3 || tuple_elements.len() > 4 {
            continue; // Skip invalid frames
        }

        // Extract module
        let module = if let eetf::Term::Atom(a) = &tuple_elements[0] {
            a.name.clone()
        } else {
            continue;
        };

        // Extract function
        let function = if let eetf::Term::Atom(a) = &tuple_elements[1] {
            a.name.clone()
        } else {
            continue;
        };

        // Extract arity
        let arity = if let Some(arity_val) = extract_integer(&tuple_elements[2]) {
            arity_val as u32
        } else {
            continue;
        };

        // Extract optional file/line from location list
        let mut file: Option<String> = None;
        let mut line: Option<u32> = None;

        if tuple_elements.len() == 4
            && let Some(location_list) = rpc::extract_list(&tuple_elements[3])
        {
            for location_entry in location_list {
                if let Some(location_tuple) = rpc::extract_tuple(location_entry)
                    && location_tuple.len() == 2
                    && let eetf::Term::Atom(key) = &location_tuple[0]
                {
                    match key.name.as_str() {
                        "file" => {
                            file = extract_string(&location_tuple[1]);
                        }
                        "line" => {
                            line = extract_integer(&location_tuple[1]).map(|v| v as u32);
                        }
                        _ => {}
                    }
                }
            }
        }

        result.push(StackFrame {
            module,
            function,
            arity,
            file,
            line,
        });
    }

    Ok(result)
}

/// Recursively builds the supervision tree by calling supervisor:which_children/1.
fn build_supervision_tree<'a>(
    connection_manager: &'a ConnectionManager,
    node: &'a str,
    sup_ref: eetf::Term,
    depth: usize,
    max_depth: usize,
    warning: &'a mut Option<String>,
    creation: u32,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = crate::error::RpcResult<SupervisionTreeNode>> + Send + 'a>,
> {
    Box::pin(async move {
        use crate::rpc;

        // Check depth limit
        if depth >= max_depth {
            if warning.is_none() {
                *warning = Some(format!(
                    "Recursion depth limit of {} reached - tree may be incomplete",
                    max_depth
                ));
            }
            // Return a placeholder node
            return Ok(SupervisionTreeNode {
                id: "...".to_string(),
                pid: None,
                child_type: "truncated".to_string(),
                modules: vec![],
                children: vec![],
            });
        }

        // Call supervisor:which_children(SupRef)
        let result = rpc::rpc_call(
            connection_manager,
            node,
            "supervisor",
            "which_children",
            vec![sup_ref.clone()],
            None,
        )
        .await;

        let children_term = match result {
            Ok(term) => term,
            Err(e) => {
                // Check if this is a "not a supervisor" error
                let error_msg = format!("{}", e);
                if error_msg.contains("undef") || error_msg.contains("noproc") {
                    return Err(crate::error::RpcError::BadRpc {
                        node: node.to_string(),
                        module: "supervisor".to_string(),
                        function: "which_children".to_string(),
                        reason: "not a supervisor or supervisor not found".to_string(),
                    });
                }
                return Err(e);
            }
        };

        // Extract the supervisor PID for the root node
        let root_pid = match &sup_ref {
            eetf::Term::Pid(pid) => Some(format_pid(pid)),
            eetf::Term::Atom(_atom) => {
                // Try to resolve registered name to PID
                // For now, we'll just use None since we don't have the PID
                // A production implementation might call erlang:whereis/1
                None
            }
            _ => None,
        };

        // Parse children list
        let children_list = match rpc::extract_list(&children_term) {
            Some(list) => list,
            None => {
                return Err(crate::error::RpcError::BadRpc {
                    node: node.to_string(),
                    module: "supervisor".to_string(),
                    function: "which_children".to_string(),
                    reason: "unexpected response format - expected list".to_string(),
                });
            }
        };

        let mut child_nodes = Vec::new();

        for child_term in children_list {
            // Each child is a tuple: {Id, Child, Type, Modules}
            // where Child can be a PID or 'undefined'
            let tuple_elements = match rpc::extract_tuple(child_term) {
                Some(elements) if elements.len() == 4 => elements,
                _ => continue, // Skip malformed entries
            };

            // Extract ID (can be atom or other term)
            let id = format_child_id(&tuple_elements[0]);

            // Extract Child PID (or undefined)
            let child_pid = match &tuple_elements[1] {
                eetf::Term::Pid(pid) => Some(format_pid(pid)),
                eetf::Term::Atom(atom) if atom.name == "undefined" => None,
                _ => None,
            };

            // Extract Type (worker or supervisor)
            let child_type = match &tuple_elements[2] {
                eetf::Term::Atom(atom) => atom.name.to_string(),
                _ => "unknown".to_string(),
            };

            // Extract Modules (list of atoms or 'dynamic')
            let modules = extract_modules(&tuple_elements[3]);

            // If this is a supervisor and has a PID, recursively expand it
            let children = if child_type == "supervisor"
                && let Some(ref pid_str) = child_pid
            {
                if let Some(pid_term) = parse_pid(pid_str, node, creation) {
                    match build_supervision_tree(
                        connection_manager,
                        node,
                        pid_term,
                        depth + 1,
                        max_depth,
                        warning,
                        creation,
                    )
                    .await
                    {
                        Ok(child_tree) => vec![child_tree],
                        Err(_) => {
                            // If we can't expand a child supervisor, just skip it
                            vec![]
                        }
                    }
                } else {
                    vec![]
                }
            } else {
                vec![]
            };

            // Flatten if we only have one child
            let final_children = if children.len() == 1 {
                children[0].children.clone()
            } else {
                vec![]
            };

            child_nodes.push(SupervisionTreeNode {
                id,
                pid: child_pid,
                child_type,
                modules,
                children: final_children,
            });
        }

        // Create the root node
        Ok(SupervisionTreeNode {
            id: format_child_id(&sup_ref),
            pid: root_pid,
            child_type: "supervisor".to_string(),
            modules: vec![],
            children: child_nodes,
        })
    })
}

/// Format a child ID term to a string.
fn format_child_id(term: &eetf::Term) -> String {
    match term {
        eetf::Term::Atom(atom) => atom.name.to_string(),
        eetf::Term::Binary(bin) => String::from_utf8_lossy(&bin.bytes).to_string(),
        eetf::Term::Pid(pid) => format_pid(pid),
        eetf::Term::FixInteger(i) => i.value.to_string(),
        eetf::Term::Tuple(t) => {
            let inner: Vec<String> = t.elements.iter().map(format_child_id).collect();
            format!("{{{}}}", inner.join(", "))
        }
        eetf::Term::List(l) => {
            // Check if it's a charlist (string)
            if let Some(s) = extract_string(term) {
                s
            } else {
                let inner: Vec<String> = l.elements.iter().map(format_child_id).collect();
                format!("[{}]", inner.join(", "))
            }
        }
        _ => format!("{:?}", term),
    }
}

/// Extract module list from a term.
fn extract_modules(term: &eetf::Term) -> Vec<String> {
    match term {
        eetf::Term::Atom(atom) if atom.name == "dynamic" => {
            vec!["dynamic".to_string()]
        }
        eetf::Term::List(l) => {
            let mut modules = Vec::new();
            for elem in &l.elements {
                if let eetf::Term::Atom(atom) = elem {
                    modules.push(atom.name.to_string());
                }
            }
            modules
        }
        _ => vec![],
    }
}

/// Formats a duration into a human-readable string.
fn format_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        format!("{}s ago", secs)
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

/// Formats bytes into a human-readable string.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

/// Extract an integer from a term (either FixInteger or BigInteger).
fn extract_integer(term: &eetf::Term) -> Option<u64> {
    match term {
        eetf::Term::FixInteger(i) => Some(i.value as u64),
        eetf::Term::BigInteger(b) => {
            use std::convert::TryInto;
            let result: Result<i64, _> = (&b.value).try_into();
            result.ok().map(|i| i as u64)
        }
        _ => None,
    }
}

/// Parse application info from application:which_applications() response.
/// Each element is a tuple: {Name, Description, Version}
fn parse_application_info(app_term: &eetf::Term) -> Option<ApplicationInfo> {
    use crate::rpc;

    // Extract tuple elements
    let tuple_elements = rpc::extract_tuple(app_term)?;
    if tuple_elements.len() != 3 {
        return None;
    }

    // Extract name (atom)
    let name = rpc::extract_atom(&tuple_elements[0])?;

    // Extract description (binary or list of integers)
    let description = extract_string(&tuple_elements[1])?;

    // Extract version (binary or list of integers)
    let version = extract_string(&tuple_elements[2])?;

    Some(ApplicationInfo {
        name: name.to_string(),
        description,
        version,
    })
}

/// Extract a string from a term (binary, charlist, or byte list).
fn extract_string(term: &eetf::Term) -> Option<String> {
    match term {
        eetf::Term::Binary(bin) => Some(String::from_utf8_lossy(&bin.bytes).to_string()),
        eetf::Term::ByteList(bl) => Some(String::from_utf8_lossy(&bl.bytes).to_string()),
        eetf::Term::List(_) => {
            let elements = crate::rpc::extract_list(term)?;
            let mut chars = Vec::new();
            for elem in elements {
                if let eetf::Term::FixInteger(fix_int) = elem {
                    chars.push(fix_int.value as u8);
                } else {
                    return None;
                }
            }
            Some(String::from_utf8_lossy(&chars).to_string())
        }
        _ => None,
    }
}

/// Parse process info from erlang:process_info/2 response.
fn parse_process_info(pid_term: &eetf::Term, info_term: &eetf::Term) -> Option<ProcessInfo> {
    use crate::rpc;

    // Format PID as string
    let pid_str = match pid_term {
        eetf::Term::Pid(pid) => format_pid(pid),
        _ => return None,
    };

    // info_term should be a list of {Key, Value} tuples
    let info_list = rpc::extract_list(info_term)?;

    let mut registered_name: Option<String> = None;
    let mut current_function: Option<String> = None;
    let mut memory: u64 = 0;
    let mut reductions: u64 = 0;
    let mut message_queue_len: u64 = 0;

    for item in info_list {
        let tuple_elements = rpc::extract_tuple(item)?;
        if tuple_elements.len() != 2 {
            continue;
        }

        let key = rpc::extract_atom(&tuple_elements[0])?;
        let value = &tuple_elements[1];

        match key {
            "registered_name" => {
                if let Some(name) = rpc::extract_atom(value) {
                    registered_name = Some(name.to_string());
                }
            }
            "current_function" => {
                current_function = format_mfa(value);
            }
            "memory" => {
                if let eetf::Term::FixInteger(i) = value {
                    memory = i.value.max(0) as u64;
                } else if let eetf::Term::BigInteger(i) = value {
                    use std::convert::TryInto;
                    memory = (&i.value).try_into().unwrap_or(0);
                }
            }
            "reductions" => {
                if let eetf::Term::FixInteger(i) = value {
                    reductions = i.value.max(0) as u64;
                } else if let eetf::Term::BigInteger(i) = value {
                    use std::convert::TryInto;
                    reductions = (&i.value).try_into().unwrap_or(0);
                }
            }
            "message_queue_len" => {
                if let eetf::Term::FixInteger(i) = value {
                    message_queue_len = i.value.max(0) as u64;
                } else if let eetf::Term::BigInteger(i) = value {
                    use std::convert::TryInto;
                    message_queue_len = (&i.value).try_into().unwrap_or(0);
                }
            }
            _ => {}
        }
    }

    Some(ProcessInfo {
        pid: pid_str,
        registered_name,
        current_function,
        memory,
        reductions,
        message_queue_len,
    })
}

/// Parse found process info from erlang:process_info/2 response for find_process tool.
fn parse_found_process_info(
    pid_term: &eetf::Term,
    info_term: &eetf::Term,
) -> Option<FoundProcessInfo> {
    use crate::rpc;

    // Format PID as string
    let pid_str = match pid_term {
        eetf::Term::Pid(pid) => format_pid(pid),
        _ => return None,
    };

    // info_term should be a list of {Key, Value} tuples
    let info_list = rpc::extract_list(info_term)?;

    let mut registered_name: Option<String> = None;
    let mut current_function: Option<String> = None;
    let mut memory: u64 = 0;

    for item in info_list {
        let tuple_elements = rpc::extract_tuple(item)?;
        if tuple_elements.len() != 2 {
            continue;
        }

        let key = rpc::extract_atom(&tuple_elements[0])?;
        let value = &tuple_elements[1];

        match key {
            "registered_name" => {
                if let Some(name) = rpc::extract_atom(value) {
                    registered_name = Some(name.to_string());
                }
            }
            "current_function" => {
                current_function = format_mfa(value);
            }
            "memory" => {
                if let eetf::Term::FixInteger(i) = value {
                    memory = i.value.max(0) as u64;
                } else if let eetf::Term::BigInteger(i) = value {
                    use std::convert::TryInto;
                    memory = (&i.value).try_into().unwrap_or(0);
                }
            }
            _ => {}
        }
    }

    Some(FoundProcessInfo {
        pid: pid_str,
        registered_name,
        current_function,
        memory,
    })
}

/// Parse top process info from erlang:process_info/2 response for top_processes tool.
fn parse_top_process_info(
    pid_term: &eetf::Term,
    info_term: &eetf::Term,
    sort_key: &str,
) -> Option<TopProcessInfo> {
    use crate::rpc;

    // Format PID as string
    let pid_str = match pid_term {
        eetf::Term::Pid(pid) => format_pid(pid),
        _ => return None,
    };

    // info_term should be a list of {Key, Value} tuples
    let info_list = rpc::extract_list(info_term)?;

    let mut registered_name: Option<String> = None;
    let mut current_function: Option<String> = None;
    let mut metric_value: u64 = 0;

    for item in info_list {
        let tuple_elements = rpc::extract_tuple(item)?;
        if tuple_elements.len() != 2 {
            continue;
        }

        let key = rpc::extract_atom(&tuple_elements[0])?;
        let value = &tuple_elements[1];

        match key {
            "registered_name" => {
                if let Some(name) = rpc::extract_atom(value) {
                    registered_name = Some(name.to_string());
                }
            }
            "current_function" => {
                current_function = format_mfa(value);
            }
            k if k == sort_key => {
                if let eetf::Term::FixInteger(i) = value {
                    metric_value = i.value.max(0) as u64;
                } else if let eetf::Term::BigInteger(i) = value {
                    use std::convert::TryInto;
                    let result: Result<i64, _> = (&i.value).try_into();
                    metric_value = result.unwrap_or(0).max(0) as u64;
                }
            }
            _ => {}
        }
    }

    Some(TopProcessInfo {
        pid: pid_str,
        registered_name,
        metric_value,
        current_function,
    })
}

/// Format a PID as a string.
fn format_pid(pid: &eetf::Pid) -> String {
    format!("<{}.{}.{}>", pid.node.name, pid.id, pid.serial)
}

/// Format an MFA (Module, Function, Arity) tuple as a string.
fn format_mfa(term: &eetf::Term) -> Option<String> {
    use crate::rpc;

    let tuple_elements = rpc::extract_tuple(term)?;
    if tuple_elements.len() != 3 {
        return None;
    }

    let module = rpc::extract_atom(&tuple_elements[0])?;
    let function = rpc::extract_atom(&tuple_elements[1])?;
    let arity = if let eetf::Term::FixInteger(i) = &tuple_elements[2] {
        i.value
    } else {
        return None;
    };

    Some(format!("{}:{}/{}", module, function, arity))
}

/// Parse a PID from a string in various formats.
///
/// Accepts:
/// - Erlang format: `<0.123.0>` (node_number.id.serial)
/// - Elixir format: `#PID<0.123.0>`
/// - Raw format: `0.123.0`
/// - Wire format: `<node@host.123.0>` (node.id.serial, as output by this tool)
fn parse_pid(pid_str: &str, node_name: &str, creation: u32) -> Option<eetf::Term> {
    let trimmed = pid_str.trim();

    // Remove wrapper if present: <...>, #PID<...>
    let inner = if let Some(stripped) = trimmed.strip_prefix("#PID<") {
        stripped.strip_suffix('>')?
    } else if let Some(stripped) = trimmed.strip_prefix('<') {
        stripped.strip_suffix('>')?
    } else {
        trimmed
    };

    // Parse id and serial from the last two dot-separated components.
    // The prefix is either a node number (e.g. "0") or a node name (e.g. "node@host").
    let last_dot = inner.rfind('.')?;
    let serial: u32 = inner[last_dot + 1..].parse().ok()?;

    let before_serial = &inner[..last_dot];
    let second_last_dot = before_serial.rfind('.')?;
    let id: u32 = before_serial[second_last_dot + 1..].parse().ok()?;

    let pid = eetf::Pid::new(node_name, id, serial, creation);
    Some(eetf::Term::Pid(pid))
}

/// Convert a Term to JSON using the current formatter for string representation.
fn term_to_json(term: &eetf::Term, formatter: &dyn TermFormatter) -> serde_json::Value {
    use crate::rpc;

    match term {
        eetf::Term::Atom(atom) => serde_json::Value::String(formatter.format_atom(&atom.name)),

        eetf::Term::FixInteger(i) => serde_json::Value::Number(i.value.into()),

        eetf::Term::BigInteger(i) => {
            use std::convert::TryInto;
            let result: Result<i64, _> = (&i.value).try_into();
            if let Ok(val) = result {
                serde_json::Value::Number(serde_json::Number::from(val))
            } else {
                serde_json::Value::String(format!("{}", i.value))
            }
        }

        eetf::Term::Float(f) => {
            if let Some(num) = serde_json::Number::from_f64(f.value) {
                serde_json::Value::Number(num)
            } else {
                serde_json::Value::String(f.value.to_string())
            }
        }

        eetf::Term::Binary(b) => {
            if let Ok(s) = String::from_utf8(b.bytes.clone()) {
                serde_json::Value::String(s)
            } else {
                serde_json::Value::String(formatter.format_binary(&b.bytes))
            }
        }

        eetf::Term::List(l) => {
            if l.is_nil() {
                serde_json::Value::Array(vec![])
            } else {
                let items: Vec<serde_json::Value> = l
                    .elements
                    .iter()
                    .map(|e| term_to_json(e, formatter))
                    .collect();
                serde_json::Value::Array(items)
            }
        }

        eetf::Term::Tuple(t) => {
            // Special handling for {Key, Value} pairs
            if t.elements.len() == 2
                && let Some(key) = rpc::extract_atom(&t.elements[0])
            {
                let value = term_to_json(&t.elements[1], formatter);
                return serde_json::json!({
                    key: value
                });
            }

            // Otherwise, represent tuple as array
            let items: Vec<serde_json::Value> = t
                .elements
                .iter()
                .map(|e| term_to_json(e, formatter))
                .collect();
            serde_json::Value::Array(items)
        }

        eetf::Term::Map(m) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in &m.map {
                let key_str = match k {
                    eetf::Term::Atom(a) => a.name.to_string(),
                    eetf::Term::Binary(b) => String::from_utf8_lossy(&b.bytes).to_string(),
                    _ => formatter.format_term(k),
                };
                obj.insert(key_str, term_to_json(v, formatter));
            }
            serde_json::Value::Object(obj)
        }

        eetf::Term::Pid(pid) => serde_json::Value::String(format_pid(pid)),

        eetf::Term::Reference(r) => serde_json::Value::String(formatter.format_reference(r)),

        _ => serde_json::Value::String(formatter.format_term(term)),
    }
}

/// Parse ETS table info from ets:info(Table) response.
fn parse_ets_table_info(info_term: &eetf::Term) -> Option<EtsTableInfo> {
    use crate::rpc;

    // ets:info returns a list of {Key, Value} tuples
    let info_list = rpc::extract_list(info_term)?;

    let mut name = None;
    let mut id = None;
    let mut size = None;
    let mut memory = None;
    let mut owner = None;
    let mut table_type = None;
    let mut protection = None;

    for item in info_list {
        let tuple_elements = rpc::extract_tuple(item)?;
        if tuple_elements.len() != 2 {
            continue;
        }

        let key = rpc::extract_atom(&tuple_elements[0])?;
        let value = &tuple_elements[1];

        match key {
            "name" => {
                name = Some(
                    rpc::extract_atom(value)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("{:?}", value)),
                );
            }
            "id" => {
                id = if let Some(atom_name) = rpc::extract_atom(value) {
                    Some(atom_name.to_string())
                } else if let Some(int_val) = extract_integer(value) {
                    Some(int_val.to_string())
                } else {
                    Some(format!("{:?}", value))
                };
            }
            "size" => {
                size = extract_integer(value);
            }
            "memory" => {
                memory = extract_integer(value);
            }
            "owner" => {
                if let eetf::Term::Pid(pid) = value {
                    owner = Some(format_pid(pid));
                }
            }
            "type" => {
                table_type = rpc::extract_atom(value).map(|s| s.to_string());
            }
            "protection" => {
                protection = rpc::extract_atom(value).map(|s| s.to_string());
            }
            _ => {}
        }
    }

    Some(EtsTableInfo {
        name: name.unwrap_or_else(|| "unknown".to_string()),
        id: id.unwrap_or_else(|| "unknown".to_string()),
        size: size.unwrap_or(0),
        memory: format_bytes(memory.unwrap_or(0)),
        owner: owner.unwrap_or_else(|| "unknown".to_string()),
        table_type: table_type.unwrap_or_else(|| "unknown".to_string()),
        protection: protection.unwrap_or_else(|| "unknown".to_string()),
    })
}

/// Parse detailed ETS table info from ets:info(Table) response.
fn parse_ets_table_detailed_info(info_term: &eetf::Term) -> Option<EtsTableDetailedInfo> {
    use crate::rpc;

    // ets:info returns a list of {Key, Value} tuples
    let info_list = rpc::extract_list(info_term)?;

    let mut name = None;
    let mut id = None;
    let mut size = None;
    let mut memory = None;
    let mut owner = None;
    let mut heir = None;
    let mut table_type = None;
    let mut protection = None;
    let mut compressed = None;
    let mut read_concurrency = None;
    let mut write_concurrency = None;
    let mut decentralized_counters = None;
    let mut keypos = None;

    for item in info_list {
        let tuple_elements = rpc::extract_tuple(item)?;
        if tuple_elements.len() != 2 {
            continue;
        }

        let key = rpc::extract_atom(&tuple_elements[0])?;
        let value = &tuple_elements[1];

        match key {
            "name" => {
                name = Some(
                    rpc::extract_atom(value)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("{:?}", value)),
                );
            }
            "id" => {
                id = if let Some(atom_name) = rpc::extract_atom(value) {
                    Some(atom_name.to_string())
                } else if let Some(int_val) = extract_integer(value) {
                    Some(int_val.to_string())
                } else {
                    Some(format!("{:?}", value))
                };
            }
            "size" => {
                size = extract_integer(value);
            }
            "memory" => {
                memory = extract_integer(value);
            }
            "owner" => {
                if let eetf::Term::Pid(pid) = value {
                    owner = Some(format_pid(pid));
                }
            }
            "heir" => {
                heir = match value {
                    eetf::Term::Atom(a) if a.name == "none" => Some("none".to_string()),
                    eetf::Term::Pid(pid) => Some(format_pid(pid)),
                    _ => None,
                };
            }
            "type" => {
                table_type = rpc::extract_atom(value).map(|s| s.to_string());
            }
            "protection" => {
                protection = rpc::extract_atom(value).map(|s| s.to_string());
            }
            "compressed" => {
                if let eetf::Term::Atom(a) = value {
                    compressed = Some(a.name == "true");
                }
            }
            "read_concurrency" => {
                if let eetf::Term::Atom(a) = value {
                    read_concurrency = Some(a.name == "true");
                }
            }
            "write_concurrency" => {
                write_concurrency = match value {
                    eetf::Term::Atom(a) if a.name == "true" => Some("true".to_string()),
                    eetf::Term::Atom(a) if a.name == "false" => Some("false".to_string()),
                    eetf::Term::Atom(a) if a.name == "auto" => Some("auto".to_string()),
                    _ => None,
                };
            }
            "decentralized_counters" => {
                if let eetf::Term::Atom(a) = value {
                    decentralized_counters = Some(a.name == "true");
                }
            }
            "keypos" => {
                keypos = extract_integer(value);
            }
            _ => {}
        }
    }

    Some(EtsTableDetailedInfo {
        id: id.unwrap_or_else(|| "unknown".to_string()),
        name: name.unwrap_or_else(|| "unknown".to_string()),
        table_type: table_type.unwrap_or_else(|| "unknown".to_string()),
        size: size.unwrap_or(0),
        memory: format_bytes(memory.unwrap_or(0)),
        owner: owner.unwrap_or_else(|| "unknown".to_string()),
        heir,
        protection: protection.unwrap_or_else(|| "unknown".to_string()),
        compressed,
        read_concurrency,
        write_concurrency,
        decentralized_counters,
        keypos: keypos.unwrap_or(1),
    })
}

/// Parse memory bytes from formatted string (e.g., "1.5 MB" -> 1500000).
fn parse_memory_bytes(memory_str: &str) -> u64 {
    // Extract numeric part
    let parts: Vec<&str> = memory_str.split_whitespace().collect();
    if parts.is_empty() {
        return 0;
    }

    let numeric_part = match parts[0].parse::<f64>() {
        Ok(n) => n,
        Err(_) => return 0,
    };

    // Get unit (if present)
    let multiplier = if parts.len() > 1 {
        match parts[1] {
            "B" => 1.0,
            "KB" => 1024.0,
            "MB" => 1024.0 * 1024.0,
            "GB" => 1024.0 * 1024.0 * 1024.0,
            _ => 1.0,
        }
    } else {
        1.0
    };

    (numeric_part * multiplier) as u64
}

#[tool_handler]
impl ServerHandler for ErlDistMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: env!("CARGO_PKG_NAME").to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                ..Default::default()
            },
            instructions: Some(
                "Erlang Distribution MCP Server - Connect to Erlang/BEAM nodes for introspection, \
                 debugging, tracing, and code evaluation. Use connect_node to establish a connection \
                 before using other tools."
                    .to_string(),
            ),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn formatter_mode_display() {
        assert_eq!(FormatterMode::Erlang.to_string(), "erlang");
        assert_eq!(FormatterMode::Elixir.to_string(), "elixir");
        assert_eq!(FormatterMode::Gleam.to_string(), "gleam");
        assert_eq!(FormatterMode::Lfe.to_string(), "lfe");
    }

    #[test]
    fn formatter_mode_from_str() {
        assert_eq!(
            "erlang".parse::<FormatterMode>().unwrap(),
            FormatterMode::Erlang
        );
        assert_eq!(
            "Erlang".parse::<FormatterMode>().unwrap(),
            FormatterMode::Erlang
        );
        assert_eq!(
            "ERLANG".parse::<FormatterMode>().unwrap(),
            FormatterMode::Erlang
        );
        assert_eq!(
            "elixir".parse::<FormatterMode>().unwrap(),
            FormatterMode::Elixir
        );
        assert_eq!(
            "gleam".parse::<FormatterMode>().unwrap(),
            FormatterMode::Gleam
        );
        assert_eq!("lfe".parse::<FormatterMode>().unwrap(), FormatterMode::Lfe);
        assert!("invalid".parse::<FormatterMode>().is_err());
    }

    #[test]
    fn server_state_new() {
        let state = ServerState::new(FormatterMode::Elixir, true);
        assert!(state.allow_eval);
    }

    #[test]
    fn server_new() {
        let server = ErlDistMcpServer::new(FormatterMode::Erlang, false);
        assert!(!server.state().allow_eval);
    }

    #[test]
    fn server_get_info() {
        let server = ErlDistMcpServer::new(FormatterMode::Erlang, false);
        let info = server.get_info();
        assert_eq!(info.server_info.name, "erl_dist_mcp");
        assert!(info.instructions.is_some());
    }

    #[test]
    fn format_duration_seconds() {
        let duration = std::time::Duration::from_secs(30);
        assert_eq!(format_duration(duration), "30s ago");
    }

    #[test]
    fn format_duration_minutes() {
        let duration = std::time::Duration::from_secs(120);
        assert_eq!(format_duration(duration), "2m ago");
    }

    #[test]
    fn format_duration_hours() {
        let duration = std::time::Duration::from_secs(7200);
        assert_eq!(format_duration(duration), "2h ago");
    }

    #[test]
    fn format_duration_days() {
        let duration = std::time::Duration::from_secs(172800);
        assert_eq!(format_duration(duration), "2d ago");
    }

    #[test]
    fn connect_node_request_deserialize() {
        let json = r#"{"node": "foo@localhost", "cookie": "secret"}"#;
        let request: ConnectNodeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.node, "foo@localhost");
        assert_eq!(request.cookie, "secret");
        assert!(request.alias.is_none());
    }

    #[test]
    fn connect_node_request_with_alias() {
        let json = r#"{"node": "foo@localhost", "cookie": "secret", "alias": "myalias"}"#;
        let request: ConnectNodeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.alias, Some("myalias".to_string()));
    }

    #[test]
    fn disconnect_node_request_deserialize() {
        let json = r#"{"node": "foo@localhost"}"#;
        let request: DisconnectNodeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.node, "foo@localhost");
    }

    #[test]
    fn set_mode_request_deserialize() {
        let json = r#"{"mode": "elixir"}"#;
        let request: SetModeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.mode, "elixir");
    }

    #[tokio::test]
    async fn server_state_set_mode() {
        let state = ServerState::new(FormatterMode::Erlang, false);
        assert_eq!(state.get_mode().await, FormatterMode::Erlang);

        state.set_mode(FormatterMode::Elixir).await;
        assert_eq!(state.get_mode().await, FormatterMode::Elixir);

        state.set_mode(FormatterMode::Gleam).await;
        assert_eq!(state.get_mode().await, FormatterMode::Gleam);

        state.set_mode(FormatterMode::Lfe).await;
        assert_eq!(state.get_mode().await, FormatterMode::Lfe);
    }

    // ========================================================================
    // json_to_term conversion tests
    // ========================================================================

    #[test]
    fn json_to_term_null() {
        let json = serde_json::Value::Null;
        let term = json_to_term(&json, "test@localhost", 0).unwrap();
        assert!(matches!(term, eetf::Term::List(l) if l.is_nil()));
    }

    #[test]
    fn json_to_term_bool_true() {
        let json = serde_json::Value::Bool(true);
        let term = json_to_term(&json, "test@localhost", 0).unwrap();
        assert!(matches!(term, eetf::Term::Atom(a) if a.name == "true"));
    }

    #[test]
    fn json_to_term_bool_false() {
        let json = serde_json::Value::Bool(false);
        let term = json_to_term(&json, "test@localhost", 0).unwrap();
        assert!(matches!(term, eetf::Term::Atom(a) if a.name == "false"));
    }

    #[test]
    fn json_to_term_integer_small() {
        let json = serde_json::json!(42);
        let term = json_to_term(&json, "test@localhost", 0).unwrap();
        assert!(matches!(term, eetf::Term::FixInteger(i) if i.value == 42));
    }

    #[test]
    fn json_to_term_integer_large() {
        let json = serde_json::json!(9_223_372_036_854_775_807i64); // i64::MAX
        let term = json_to_term(&json, "test@localhost", 0).unwrap();
        assert!(matches!(term, eetf::Term::BigInteger(_)));
    }

    #[test]
    fn json_to_term_float() {
        let json = serde_json::json!(42.5);
        let term = json_to_term(&json, "test@localhost", 0).unwrap();
        if let eetf::Term::Float(f) = term {
            assert!((f.value - 42.5).abs() < 0.001);
        } else {
            panic!("Expected Float");
        }
    }

    #[test]
    fn json_to_term_string() {
        let json = serde_json::json!("hello");
        let term = json_to_term(&json, "test@localhost", 0).unwrap();
        if let eetf::Term::Binary(b) = term {
            assert_eq!(b.bytes, b"hello");
        } else {
            panic!("Expected Binary");
        }
    }

    #[test]
    fn json_to_term_array_empty() {
        let json = serde_json::json!([]);
        let term = json_to_term(&json, "test@localhost", 0).unwrap();
        if let eetf::Term::List(l) = term {
            assert_eq!(l.elements.len(), 0);
        } else {
            panic!("Expected List");
        }
    }

    #[test]
    fn json_to_term_array_with_elements() {
        let json = serde_json::json!([1, 2, 3]);
        let term = json_to_term(&json, "test@localhost", 0).unwrap();
        if let eetf::Term::List(l) = term {
            assert_eq!(l.elements.len(), 3);
        } else {
            panic!("Expected List");
        }
    }

    #[test]
    fn json_to_term_array_mixed_types() {
        let json = serde_json::json!([1, "hello", true, null]);
        let term = json_to_term(&json, "test@localhost", 0).unwrap();
        if let eetf::Term::List(l) = term {
            assert_eq!(l.elements.len(), 4);
            assert!(matches!(l.elements[0], eetf::Term::FixInteger(_)));
            assert!(matches!(l.elements[1], eetf::Term::Binary(_)));
            assert!(matches!(l.elements[2], eetf::Term::Atom(_)));
            assert!(matches!(l.elements[3], eetf::Term::List(ref nl) if nl.is_nil()));
        } else {
            panic!("Expected List");
        }
    }

    #[test]
    fn json_to_term_object_regular_map() {
        let json = serde_json::json!({"key": "value", "number": 42});
        let term = json_to_term(&json, "test@localhost", 0).unwrap();
        if let eetf::Term::Map(m) = term {
            assert_eq!(m.map.len(), 2);
        } else {
            panic!("Expected Map");
        }
    }

    #[test]
    fn json_to_term_object_atom() {
        let json = serde_json::json!({"__atom__": "ok"});
        let term = json_to_term(&json, "test@localhost", 0).unwrap();
        assert!(matches!(term, eetf::Term::Atom(a) if a.name == "ok"));
    }

    #[test]
    fn json_to_term_object_atom_invalid() {
        let json = serde_json::json!({"__atom__": 123});
        let result = json_to_term(&json, "test@localhost", 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be a string"));
    }

    #[test]
    fn json_to_term_object_pid_erlang_format() {
        let json = serde_json::json!({"__pid__": "<0.123.0>"});
        let term = json_to_term(&json, "test@localhost", 0).unwrap();
        assert!(matches!(term, eetf::Term::Pid(_)));
    }

    #[test]
    fn json_to_term_object_pid_elixir_format() {
        let json = serde_json::json!({"__pid__": "#PID<0.123.0>"});
        let term = json_to_term(&json, "test@localhost", 0).unwrap();
        assert!(matches!(term, eetf::Term::Pid(_)));
    }

    #[test]
    fn json_to_term_object_pid_raw_format() {
        let json = serde_json::json!({"__pid__": "0.123.0"});
        let term = json_to_term(&json, "test@localhost", 0).unwrap();
        assert!(matches!(term, eetf::Term::Pid(_)));
    }

    #[test]
    fn json_to_term_object_pid_invalid() {
        let json = serde_json::json!({"__pid__": "invalid"});
        let result = json_to_term(&json, "test@localhost", 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid PID format"));
    }

    #[test]
    fn json_to_term_object_pid_not_string() {
        let json = serde_json::json!({"__pid__": 123});
        let result = json_to_term(&json, "test@localhost", 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be a string"));
    }

    #[test]
    fn json_to_term_nested_structure() {
        let json = serde_json::json!({
            "user": "alice",
            "age": 30,
            "active": true,
            "tags": ["admin", "developer"],
            "metadata": {
                "created": "2024-01-01",
                "status": {"__atom__": "active"}
            }
        });
        let term = json_to_term(&json, "test@localhost", 0).unwrap();
        assert!(matches!(term, eetf::Term::Map(_)));
    }

    #[test]
    fn rpc_call_request_deserialize() {
        let json = r#"{
            "node": "node@localhost",
            "module": "erlang",
            "function": "node",
            "args": []
        }"#;
        let request: RpcCallRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.node, "node@localhost");
        assert_eq!(request.module, "erlang");
        assert_eq!(request.function, "node");
        assert_eq!(request.args.len(), 0);
    }

    #[test]
    fn rpc_call_request_with_args() {
        let json = r#"{
            "node": "node@localhost",
            "module": "lists",
            "function": "reverse",
            "args": [[1, 2, 3]]
        }"#;
        let request: RpcCallRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.args.len(), 1);
        assert!(matches!(request.args[0], serde_json::Value::Array(_)));
    }

    #[test]
    fn eval_code_request_deserialize() {
        let json = r#"{
            "node": "node@localhost",
            "code": "X + Y."
        }"#;
        let request: EvalCodeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.node, "node@localhost");
        assert_eq!(request.code, "X + Y.");
        assert!(request.bindings.is_none());
    }

    #[test]
    fn eval_code_request_with_bindings() {
        let json = r#"{
            "node": "node@localhost",
            "code": "X + Y.",
            "bindings": {"X": 10, "Y": 20}
        }"#;
        let request: EvalCodeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.node, "node@localhost");
        assert_eq!(request.code, "X + Y.");
        assert!(request.bindings.is_some());

        if let Some(serde_json::Value::Object(obj)) = request.bindings {
            assert_eq!(obj.len(), 2);
            assert!(obj.contains_key("X"));
            assert!(obj.contains_key("Y"));
        } else {
            panic!("Expected bindings to be an object");
        }
    }

    #[test]
    fn eval_code_request_with_complex_bindings() {
        let json = r#"{
            "node": "node@localhost",
            "code": "maps:get(name, User).",
            "bindings": {
                "User": {
                    "name": "alice",
                    "age": 30,
                    "active": true
                }
            }
        }"#;
        let request: EvalCodeRequest = serde_json::from_str(json).unwrap();
        assert!(request.bindings.is_some());
    }
}
