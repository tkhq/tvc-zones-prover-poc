use crate::{response::AppError, state::AppState};
use axum::{Json, extract::State};
use qos_core::protocol::services::boot::VersionedManifestEnvelope;
use qos_nsm::types::{NsmRequest, NsmResponse};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use tempo_zone_stubs::{BatchOutput, BatchWitness, prover};

/// Request body for `POST /prove_zone_batch`.
#[derive(Serialize, Deserialize)]
pub struct ProveZoneBatchRequest {
    /// The JSON serialized batch witness (matching the tempo zones prover
    /// input definitions), encrypted to the enclave's quorum public key
    /// with qos_p256. Callers fetch the quorum key from the attested
    /// manifest via `GET /enclave_identity` before encrypting.
    #[serde(with = "qos_hex::serde")]
    pub encrypted_witness: Vec<u8>,
}

/// Response body for `POST /prove_zone_batch`.
#[derive(Serialize, Deserialize)]
pub struct ProveZoneBatchResponse {
    /// The [`BatchOutput`] produced by the zone prover, as structured JSON.
    /// Both signatures are over its canonical QOS JSON (`qos_json`)
    /// encoding: verifiers re-serialize this value with `qos_json::to_vec`
    /// to reconstruct the exact signed bytes.
    pub batch_output: BatchOutput,
    /// The quorum key's signature over the batch output.
    #[serde(with = "qos_hex::serde")]
    pub quorum_key_signature: Vec<u8>,
    /// The quorum signing public key.
    #[serde(with = "qos_hex::serde")]
    pub quorum_public_key: Vec<u8>,
    /// The ephemeral key's signature over the batch output.
    #[serde(with = "qos_hex::serde")]
    pub ephemeral_key_signature: Vec<u8>,
    /// The ephemeral signing public key.
    #[serde(with = "qos_hex::serde")]
    pub ephemeral_public_key: Vec<u8>,
    /// COSE Sign1 NSM attestation document with the sha256 of the canonical
    /// QOS JSON batch output bytes in `user_data` and the ephemeral public
    /// key in `public_key`. The full batch output does not fit the NSM's
    /// `user_data` size limit, so the document commits to its hash.
    #[serde(with = "qos_hex::serde")]
    pub attestation_doc: Vec<u8>,
    /// The QOS v2 manifest envelope loaded at server startup, as structured
    /// JSON. Verifiers recompute the attested manifest hash from this value
    /// with the canonical QOS JSON hash.
    pub manifest: VersionedManifestEnvelope,
}

/// Decrypt the request's witness with the enclave's quorum key and run
/// the prover over it.
fn decrypt_and_prove(
    state: &AppState,
    request: &ProveZoneBatchRequest,
) -> Result<BatchOutput, AppError> {
    let witness_json = state
        .quorum_key
        .decrypt(&request.encrypted_witness)
        .map_err(|e| {
            AppError::bad_request(format!(
                "failed to decrypt witness with the enclave's quorum key: {e:?}"
            ))
        })?;
    let witness: BatchWitness = serde_json::from_slice(&witness_json)
        .map_err(|e| AppError::bad_request(format!("decrypted witness is not valid JSON: {e}")))?;
    prover::prove_zone_batch(&witness)
        .map_err(|e| AppError::bad_request(format!("invalid batch witness: {e}")))
}

/// Prove a zone batch: decrypt and prove the witness, sign the canonical
/// QOS JSON batch output bytes with the quorum and ephemeral keys, and
/// attach an NSM attestation doc committing to `sha256(batch_output)` plus
/// the QOS manifest.
pub(crate) async fn prove_zone_batch(
    State(state): State<AppState>,
    Json(request): Json<ProveZoneBatchRequest>,
) -> Result<Json<ProveZoneBatchResponse>, AppError> {
    let output = decrypt_and_prove(&state, &request)?;

    // Canonical QOS JSON: the signing payload. Verifiers recompute exactly
    // these bytes by re-serializing the response's structured batch_output.
    let signed_payload = qos_json::to_vec(&output)
        .map_err(|e| AppError::internal(format!("failed to serialize batch output: {e}")))?;
    let quorum_key_signature = state
        .quorum_key
        .sign(&signed_payload)
        .map_err(|e| AppError::internal(format!("failed to sign with quorum key: {e:?}")))?;
    let ephemeral_key_signature = state
        .ephemeral_key
        .sign(&signed_payload)
        .map_err(|e| AppError::internal(format!("failed to sign with ephemeral key: {e:?}")))?;
    let ephemeral_public_key = state.ephemeral_key.public_key().to_bytes();

    // Commit to the hash of the batch output: the NSM caps `user_data` at
    // 512 bytes, so the full serialized batch output cannot be embedded.
    let user_data = sha2::Sha256::digest(&signed_payload).to_vec();
    let nsm_response = state.nsm.nsm_process_request(NsmRequest::Attestation {
        user_data: Some(user_data),
        nonce: None,
        public_key: Some(ephemeral_public_key.clone()),
    });
    let NsmResponse::Attestation { document } = nsm_response else {
        return Err(AppError::internal(format!(
            "unexpected NSM response: {nsm_response:?}"
        )));
    };

    Ok(Json(ProveZoneBatchResponse {
        batch_output: output,
        quorum_key_signature,
        quorum_public_key: state.quorum_key.public_key().to_bytes(),
        ephemeral_key_signature,
        ephemeral_public_key,
        attestation_doc: document,
        manifest: state.manifest_envelope(),
    }))
}
