//! CLI argument parsing for the Zones prover server
use clap::Parser;

/// Zones prover REST server
#[derive(Parser, Debug)]
#[command(name = "zones_prover", version, about = "Zones prover REST server")]
pub struct Cli {
    /// IP address to listen on
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Port to listen on
    #[arg(long, default_value = "3000")]
    pub port: u16,

    /// Path to the quorum key file
    #[arg(long, default_value = qos_core::QUORUM_FILE)]
    pub quorum_file: String,

    /// Path to the ephemeral key file used for app proofs
    #[arg(long, default_value = qos_core::EPHEMERAL_KEY_FILE)]
    pub ephemeral_file: String,

    /// Path to the QOS manifest file. Override for local testing.
    #[arg(long, default_value = qos_core::MANIFEST_FILE)]
    pub manifest_file: String,

    /// Use a mock NSM that builds structurally real attestation documents
    /// instead of the real Nitro Secure Module. For local testing outside
    /// an enclave.
    #[arg(long)]
    pub mock_nsm: bool,
}
