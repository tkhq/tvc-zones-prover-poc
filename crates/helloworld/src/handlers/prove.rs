use crate::{response::AppError, state::AppState, zone_prover};
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

// Placeholder values until the app runs inside an enclave and can request a
// real NSM attestation document and read the QOS manifest.
const STUB_ATTESTATION_DOC: &[u8] = b"stub-attestation-doc";
const STUB_MANIFEST: &[u8] = b"stub-manifest";

#[derive(Deserialize)]
pub(crate) struct ProveZoneBatchRequest {
    /// Hex encoded batch witness to prove over.
    witness: String,
}

#[derive(Serialize)]
pub(crate) struct ProveZoneBatchResponse {
    /// The serialized batch output produced by the zone prover. Both
    /// signatures are over exactly these bytes.
    #[serde(with = "qos_hex::serde")]
    batch_output: Vec<u8>,
    /// The quorum key's signature over the batch output.
    #[serde(with = "qos_hex::serde")]
    quorum_key_signature: Vec<u8>,
    /// The quorum signing public key.
    #[serde(with = "qos_hex::serde")]
    quorum_public_key: Vec<u8>,
    /// The ephemeral key's signature over the batch output.
    #[serde(with = "qos_hex::serde")]
    ephemeral_key_signature: Vec<u8>,
    /// The ephemeral signing public key.
    #[serde(with = "qos_hex::serde")]
    ephemeral_public_key: Vec<u8>,
    /// NSM attestation document (stub).
    #[serde(with = "qos_hex::serde")]
    attestation_doc: Vec<u8>,
    /// QOS manifest (stub).
    #[serde(with = "qos_hex::serde")]
    manifest: Vec<u8>,
}

pub(crate) async fn prove_zone_batch(
    State(state): State<AppState>,
    Json(request): Json<ProveZoneBatchRequest>,
) -> Result<Json<ProveZoneBatchResponse>, AppError> {
    let witness = qos_hex::decode(&request.witness)
        .map_err(|e| AppError::bad_request(format!("invalid witness hex: {e:?}")))?;

    let batch_output = zone_prover::prove_zone_batch(&witness);

    let quorum_key_signature = state
        .quorum_key
        .sign(&batch_output)
        .map_err(|e| AppError::internal(format!("failed to sign with quorum key: {e:?}")))?;
    let ephemeral_key_signature = state
        .ephemeral_key
        .sign(&batch_output)
        .map_err(|e| AppError::internal(format!("failed to sign with ephemeral key: {e:?}")))?;

    Ok(Json(ProveZoneBatchResponse {
        batch_output,
        quorum_key_signature,
        quorum_public_key: state.quorum_key.public_key().to_bytes(),
        ephemeral_key_signature,
        ephemeral_public_key: state.ephemeral_key.public_key().to_bytes(),
        attestation_doc: STUB_ATTESTATION_DOC.to_vec(),
        manifest: STUB_MANIFEST.to_vec(),
    }))
}
