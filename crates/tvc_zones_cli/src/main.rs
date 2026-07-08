//! CLI for verifying a live TVC zones prover deployment, in two labeled
//! phases: [`sequencer`] fetches and verifies the enclave identity and
//! submits an encrypted batch witness; [`onchain`] verifies the prove
//! response the way an on-chain verifier contract would. See each module
//! for its step-by-step reference implementation.
//!
//! The default posture assumes live infrastructure with a real NSM.
//! Mock attestation documents cannot chain to the AWS root; pass
//! `--unsafe-skip-root-verification` to skip root verification only, with
//! a loud warning, so every other check still runs locally.

mod attest;
mod onchain;
mod sequencer;

use clap::Parser;

/// Verify a TVC zones prover deployment: emulate the sequencer submitting a
/// batch, then an on-chain verifier checking the response.
#[derive(Parser, Debug)]
#[command(
    name = "tvc_zones_cli",
    version,
    about = "TVC zones prover verification CLI"
)]
struct Cli {
    /// Base URL of the TVC app (e.g. http://127.0.0.1:3000)
    #[arg(long, default_value = "http://127.0.0.1:3000")]
    url: String,

    /// UNSAFE: skip verifying attestation doc certificate chains against
    /// the AWS Nitro root. Attestation documents are then NOT
    /// authenticated. Only for local servers running --mock-nsm, whose mock
    /// documents cannot chain to the AWS root. Never use against production
    /// infrastructure.
    #[arg(long)]
    unsafe_skip_root_verification: bool,
}

async fn run(cli: Cli) -> Result<(), String> {
    let base_url = cli.url.trim_end_matches('/').to_string();
    let client = reqwest::Client::new();

    println!("==============================================================");
    println!("PHASE 1: SEQUENCER - fetch identity, encrypt + submit witness");
    println!("==============================================================");
    let response =
        sequencer::emulate_sequencer(&client, &base_url, cli.unsafe_skip_root_verification).await?;

    println!();
    println!("==============================================================");
    println!("PHASE 2: ON-CHAIN VERIFIER - verify the prove response");
    println!("==============================================================");
    onchain::emulate_onchain_verifier(&response, cli.unsafe_skip_root_verification)?;

    println!("\nall checks passed");
    if cli.unsafe_skip_root_verification {
        println!(
            "(EXCEPT root verification, which was skipped via --unsafe-skip-root-verification)"
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("FAILED: {e}");
        std::process::exit(1);
    }
}
