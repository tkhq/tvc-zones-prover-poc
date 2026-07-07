//! Route handlers for the zone prover REST server.

mod basic;
mod prove;

pub(crate) use basic::health;
pub(crate) use prove::{mock_attestation_prove_zone_batch, prove_zone_batch};
