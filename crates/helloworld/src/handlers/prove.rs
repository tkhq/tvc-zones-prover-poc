use crate::{response::AppError, state::AppState, zone_prover};
use axum::{Json, extract::State};
use qos_nsm::types::{NsmRequest, NsmResponse};
use serde::{Deserialize, Serialize};

// Placeholder values returned by the mock attestation endpoint.
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
    /// COSE Sign1 NSM attestation document with the batch output in
    /// `user_data` and the ephemeral public key in `public_key`.
    #[serde(with = "qos_hex::serde")]
    attestation_doc: Vec<u8>,
    /// Borsh encoded QOS manifest envelope.
    #[serde(with = "qos_hex::serde")]
    manifest: Vec<u8>,
}

/// Run the stub prover over the request's witness and sign the batch output
/// with both keys. Returns a response with the attestation doc and manifest
/// left empty for the caller to fill in.
fn prove_and_sign(
    state: &AppState,
    request: &ProveZoneBatchRequest,
) -> Result<ProveZoneBatchResponse, AppError> {
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

    Ok(ProveZoneBatchResponse {
        batch_output,
        quorum_key_signature,
        quorum_public_key: state.quorum_key.public_key().to_bytes(),
        ephemeral_key_signature,
        ephemeral_public_key: state.ephemeral_key.public_key().to_bytes(),
        attestation_doc: Vec::new(),
        manifest: Vec::new(),
    })
}

/// Prove a zone batch with a real NSM attestation doc committing to the batch
/// output in `user_data`, plus the QOS manifest read from disk.
pub(crate) async fn prove_zone_batch(
    State(state): State<AppState>,
    Json(request): Json<ProveZoneBatchRequest>,
) -> Result<Json<ProveZoneBatchResponse>, AppError> {
    let mut response = prove_and_sign(&state, &request)?;

    let nsm_response = state.nsm.nsm_process_request(NsmRequest::Attestation {
        user_data: Some(response.batch_output.clone()),
        nonce: None,
        public_key: Some(response.ephemeral_public_key.clone()),
    });
    let NsmResponse::Attestation { document } = nsm_response else {
        return Err(AppError::internal(format!(
            "unexpected NSM response: {nsm_response:?}"
        )));
    };
    response.attestation_doc = document;

    response.manifest = std::fs::read(&*state.manifest_file).map_err(|e| {
        AppError::internal(format!(
            "failed to read manifest file {}: {e}",
            state.manifest_file
        ))
    })?;

    Ok(Json(response))
}

/// Prove a zone batch with stub attestation doc and manifest values. Useful
/// for exercising the flow outside of an enclave, where the NSM and QOS
/// manifest are not available.
pub(crate) async fn mock_attestation_prove_zone_batch(
    State(state): State<AppState>,
    Json(request): Json<ProveZoneBatchRequest>,
) -> Result<Json<ProveZoneBatchResponse>, AppError> {
    let mut response = prove_and_sign(&state, &request)?;
    response.attestation_doc = STUB_ATTESTATION_DOC.to_vec();
    response.manifest = STUB_MANIFEST.to_vec();

    Ok(Json(response))
}
