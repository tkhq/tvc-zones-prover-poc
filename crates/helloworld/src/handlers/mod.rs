//! Route handlers for the zone prover REST server.

mod basic;
mod prove;

pub(crate) use basic::health;
pub(crate) use prove::prove_zone_batch;
