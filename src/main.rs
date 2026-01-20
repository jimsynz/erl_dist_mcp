//! Erlang Distribution MCP Server - Main entry point.
//!
//! This binary starts the MCP server with stdio transport.

use clap::Parser;
use erl_dist_mcp::{ErlDistMcpServer, FormatterMode};
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use tracing_subscriber::EnvFilter;

/// Erlang Distribution MCP Server
///
/// Connects to Erlang/BEAM nodes via the distribution protocol, exposing tools
/// for introspection, debugging, tracing, and code evaluation.
#[derive(Parser, Debug)]
#[command(name = "erl_dist_mcp")]
#[command(version, about, long_about = None)]
struct Args {
    /// Output format mode for displaying Erlang terms.
    #[arg(long, default_value = "erlang", value_parser = parse_mode)]
    mode: FormatterMode,

    /// Allow code evaluation tools (rpc_call, eval_code).
    /// WARNING: This enables execution of arbitrary code on connected nodes.
    #[arg(long, default_value = "false")]
    allow_eval: bool,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info")]
    log_level: String,
}

fn parse_mode(s: &str) -> Result<FormatterMode, String> {
    s.parse()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let filter = EnvFilter::try_new(&args.log_level).unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    tracing::info!(
        "Starting erl_dist_mcp server (mode: {}, allow_eval: {})",
        args.mode,
        args.allow_eval
    );

    let server = ErlDistMcpServer::new(args.mode, args.allow_eval);
    let service = server.serve(stdio()).await?;
    service.waiting().await?;

    Ok(())
}
