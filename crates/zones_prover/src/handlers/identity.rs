use crate::{response::AppError, state::AppState};
use axum::{Json, extract::State};
use qos_core::protocol::services::boot::VersionedManifestEnvelope;
use qos_nsm::types::{NsmRequest, NsmResponse};
use serde::{Deserialize, Serialize};

/// Response body for `GET /enclave_identity`.
#[derive(Serialize, Deserialize)]
pub struct EnclaveIdentityResponse {
    /// The QOS v2 manifest envelope loaded at server startup, as structured
    /// JSON. Verifiers recompute the attested manifest hash from this value
    /// with the canonical QOS JSON hash.
    pub manifest: VersionedManifestEnvelope,
    /// The quorum signing public key. Callers encrypt request payloads to
    /// this key after verifying it against the attested manifest.
    #[serde(with = "qos_hex::serde")]
    pub quorum_public_key: Vec<u8>,
    /// The per-instance ephemeral public key, bound to the enclave via the
    /// attestation doc's `public_key` field.
    #[serde(with = "qos_hex::serde")]
    pub ephemeral_public_key: Vec<u8>,
    /// Fresh COSE Sign1 NSM attestation document with the canonical QOS
    /// JSON manifest hash in `user_data` (per the QOS convention) and the
    /// ephemeral public key in `public_key`.
    #[serde(with = "qos_hex::serde")]
    pub attestation_doc: Vec<u8>,
}

/// Return the enclave's identity: the QOS manifest, the quorum and
/// ephemeral public keys, and a fresh NSM attestation document binding the
/// ephemeral key and manifest hash to the enclave.
pub(crate) async fn enclave_identity(
    State(state): State<AppState>,
) -> Result<Json<EnclaveIdentityResponse>, AppError> {
    let ephemeral_public_key = state.ephemeral_key.public_key().to_bytes();

    let nsm_response = state.nsm.nsm_process_request(NsmRequest::Attestation {
        user_data: Some(state.manifest_hash().to_vec()),
        nonce: None,
        public_key: Some(ephemeral_public_key.clone()),
    });
    let NsmResponse::Attestation { document } = nsm_response else {
        return Err(AppError::internal(format!(
            "unexpected NSM response: {nsm_response:?}"
        )));
    };

    Ok(Json(EnclaveIdentityResponse {
        manifest: state.manifest_envelope(),
        quorum_public_key: state.quorum_key.public_key().to_bytes(),
        ephemeral_public_key,
        attestation_doc: document,
    }))
}
