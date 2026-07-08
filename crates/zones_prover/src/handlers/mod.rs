//! Route handlers for the zone prover REST server.

mod basic;
mod identity;
mod prove;

pub(crate) use basic::health;
pub(crate) use identity::enclave_identity;
pub(crate) use prove::prove_zone_batch;

pub use identity::EnclaveIdentityResponse;
pub use prove::{
    EphemeralKeyProof, NsmProof, ProveZoneBatchRequest, ProveZoneBatchResponse, QuorumKeyProof,
};
