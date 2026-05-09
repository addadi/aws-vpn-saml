mod challenge;
mod config;
mod saml_server;
mod state;

use clap::Parser;
use std::process;
use tracing::{error, info, Level};
use tracing_subscriber::EnvFilter;

use config::Config;
use state::StateMachine;

fn preprocess_go_flags(args: Vec<String>) -> Vec<String> {
    let mut out = vec![args[0].clone()];
    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if arg == "-ovpn" && i + 1 < args.len() {
            out.push("--ovpn-bin".into());
            i += 1;
            out.push(args[i].clone());
        } else if arg == "-config" && i + 1 < args.len() {
            out.push("--ovpn-conf".into());
            i += 1;
            out.push(args[i].clone());
        } else if arg == "-on-challenge" && i + 1 < args.len() {
            out.push("--on-challenge".into());
            i += 1;
            out.push(args[i].clone());
        } else if arg == "-verbose" {
            out.push("--verbose".into());
        } else {
            out.push(arg.clone());
        }
        i += 1;
    }
    out
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let args = preprocess_go_flags(args);
    let config = Config::parse_from(args);

    let log_level = if config.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(log_level.into()))
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    info!(version = env!("CARGO_PKG_VERSION"), "aws-vpn-saml starting");

    let rt = tokio::runtime::Runtime::new().unwrap_or_else(|e| {
        eprintln!("failed to create tokio runtime: {e}");
        process::exit(1);
    });

    let result = rt.block_on(async { run(config).await });

    match result {
        Ok(()) => process::exit(0),
        Err(e) => {
            error!(error = %e, "fatal error");
            process::exit(e.exit_code());
        }
    }
}

async fn run(config: Config) -> Result<(), state::Error> {
    let mut sm = StateMachine::new(config);
    sm.run().await
}
