//! Reference implementation of the SEQUENCER role.
//!
//! What a sequencer does to submit a zone batch to the enclave:
//!
//! 1. `GET /enclave_identity`, decoded into [`EnclaveIdentityResponse`].
//! 2. Verify the identity attestation doc: root chain (unless skipped),
//!    `user_data` == canonical QOS JSON manifest hash (the QOS convention),
//!    and the PCR17 live manifest commitment.
//! 3. Extract the ephemeral key FROM the attestation doc (never from the
//!    unauthenticated JSON field) and the quorum key FROM the attested
//!    manifest.
//! 4. Encrypt the `BatchWitness` to the attested quorum key (qos_p256).
//!    Ephemeral keys are per-replica; until TVC ships an endpoint listing
//!    all live enclaves for an app (so a sequencer could encrypt to every
//!    relevant ephemeral key), the demo encrypts to the quorum key.
//! 5. `POST /prove_zone_batch`, decoded into [`ProveZoneBatchResponse`].
//! 6. Verify the response: the batch output matches the locally computed
//!    one and both signatures verify over the locally re-serialized
//!    canonical QOS JSON payload. The quorum key must match the attested
//!    manifest; the ephemeral key is authenticated via the response's OWN
//!    attestation doc (the replica that proves the batch may not be the
//!    replica that served the identity, so the identity's ephemeral key
//!    cannot be assumed here).

use qos_core::protocol::services::boot::VersionedManifestEnvelope;
use qos_core::protocol::services::boot::manifest::canonical_json_hash;
use qos_nsm::nitro::{
    LIVE_MANIFEST_COMMITMENT_PCR_INDEX, ManifestCommitmentKind, unsafe_attestation_doc_from_der,
    verify_attestation_doc_manifest_commitment,
};
use qos_p256::P256Public;
use tempo_zone_stubs::fixtures::example_witness;
use tempo_zone_stubs::prover::prove_zone_batch;
use zones_prover::{EnclaveIdentityResponse, ProveZoneBatchRequest, ProveZoneBatchResponse};

use crate::attest::{verify_attestation_doc_root, verify_signature};

/// Emulate what the SEQUENCER does to submit a zone batch to the enclave.
/// Returns the prove response for the on-chain verifier phase.
pub async fn emulate_sequencer(
    client: &reqwest::Client,
    base_url: &str,
    unsafe_skip_root_verification: bool,
) -> Result<ProveZoneBatchResponse, String> {
    // 1. Fetch the enclave identity.
    let identity_url = format!("{base_url}/enclave_identity");
    println!("\nsequencer step 1: GET {identity_url}");
    let identity: EnclaveIdentityResponse = client
        .get(&identity_url)
        .send()
        .await
        .map_err(|e| format!("identity request failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("identity response does not decode as EnclaveIdentityResponse: {e}"))?;
    println!("ok: decoded EnclaveIdentityResponse");

    // 2. Verify the identity attestation doc.
    println!("\nsequencer step 2: verify identity attestation doc");
    let identity_doc = unsafe_attestation_doc_from_der(&identity.attestation_doc)
        .map_err(|e| format!("identity attestation doc does not decode: {e:?}"))?;
    verify_attestation_doc_root(&identity.attestation_doc, unsafe_skip_root_verification)?;
    // The manifest arrives as structured JSON, already decoded into the
    // full manifest envelope type: recompute the attested hash locally.
    let VersionedManifestEnvelope::V2(envelope) = &identity.manifest else {
        return Err("manifest is not a v2 manifest envelope".to_string());
    };
    let manifest_hash = canonical_json_hash(&envelope.manifest);
    let identity_user_data = identity_doc
        .user_data
        .as_ref()
        .ok_or("identity attestation doc has no user_data")?;
    if identity_user_data.as_ref() != manifest_hash {
        return Err(format!(
            "identity attestation user_data does not commit to the manifest:\n  user_data:     {}\n  manifest hash: {}",
            qos_hex::encode(identity_user_data),
            qos_hex::encode(&manifest_hash)
        ));
    }
    verify_attestation_doc_manifest_commitment(
        &identity_doc,
        ManifestCommitmentKind::Live,
        &manifest_hash,
    )
    .map_err(|e| format!("live manifest commitment verification failed: {e:?}"))?;
    if envelope.manifest.namespace.quorum_key != identity.quorum_public_key {
        return Err("manifest quorum key does not match the identity quorum key".to_string());
    }
    println!(
        "ok: user_data == manifest hash, PCR{LIVE_MANIFEST_COMMITMENT_PCR_INDEX} live manifest \
         commitment, manifest quorum key == identity quorum key"
    );

    // 3. Extract the ephemeral key from the attestation doc and the quorum
    //    key from the attested manifest.
    println!(
        "\nsequencer step 3: extract ephemeral key FROM the attestation doc and quorum key \
         FROM the attested manifest"
    );
    let attested_ephemeral_key = identity_doc
        .public_key
        .as_ref()
        .ok_or("identity attestation doc has no public_key")?
        .to_vec();
    let attested_quorum_key = envelope.manifest.namespace.quorum_key.clone();
    let encrypt_key = P256Public::from_bytes(&attested_quorum_key)
        .map_err(|e| format!("attested quorum key is not a valid P256 public key: {e:?}"))?;
    println!("ok: both keys extracted from attested sources only");

    // 4. Encrypt the witness to the attested quorum key (ephemeral keys
    //    are per-replica; see the module docs).
    println!("\nsequencer step 4: encrypt BatchWitness to the attested quorum key");
    let witness = example_witness();
    let expected_output =
        prove_zone_batch(&witness).map_err(|e| format!("example witness does not prove: {e}"))?;
    let witness_json =
        serde_json::to_vec(&witness).map_err(|e| format!("failed to serialize witness: {e}"))?;
    let encrypted_witness = encrypt_key
        .encrypt(&witness_json)
        .map_err(|e| format!("failed to encrypt witness to the quorum key: {e:?}"))?;
    println!(
        "ok: created fake BatchWitness (1 zone block, 1 deposit) and encrypted it ({} -> {} bytes)",
        witness_json.len(),
        encrypted_witness.len()
    );

    // 5. Submit the encrypted witness.
    let prove_url = format!("{base_url}/prove_zone_batch");
    println!("\nsequencer step 5: POST {prove_url}");
    let resp = client
        .post(&prove_url)
        .json(&ProveZoneBatchRequest { encrypted_witness })
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("failed to read response body: {e}"))?;
    if !status.is_success() {
        return Err(format!("unexpected status {status}: {body}"));
    }
    println!("ok: HTTP {status}");
    let response: ProveZoneBatchResponse = serde_json::from_str(&body)
        .map_err(|e| format!("response does not decode as ProveZoneBatchResponse: {e}"))?;

    // 6. Verify the response against the locally computed output and the
    //    attested keys.
    println!("\nsequencer step 6: verify response");
    if response.batch_output != expected_output {
        return Err(format!(
            "batch_output does not match the locally computed output:\n  got:      {:?}\n  expected: {expected_output:?}",
            response.batch_output
        ));
    }
    println!("ok: batch_output matches the locally computed BatchOutput");
    // The response carries the BatchOutput as structured JSON; the signed
    // bytes are its canonical QOS JSON encoding. Re-serialize locally and
    // verify the signatures over exactly those recomputed bytes, never over
    // unparsed response bytes.
    let signed_payload = qos_json::to_vec(&response.batch_output)
        .map_err(|e| format!("failed to canonically serialize the batch output: {e}"))?;
    if response.quorum_public_key != attested_quorum_key {
        return Err("response quorum key does not match the attested manifest quorum key".to_string());
    }
    // The response may come from a different replica than the identity
    // call, so its ephemeral key is authenticated via the response's own
    // attestation doc: same manifest commitment (PCR17), ephemeral key in
    // `public_key`, and sha256 of the signing payload in `user_data`.
    let response_doc = unsafe_attestation_doc_from_der(&response.attestation_doc)
        .map_err(|e| format!("response attestation doc does not decode: {e:?}"))?;
    verify_attestation_doc_root(&response.attestation_doc, unsafe_skip_root_verification)?;
    let response_doc_key = response_doc
        .public_key
        .as_ref()
        .ok_or("response attestation doc has no public_key")?;
    if response_doc_key.as_ref() != response.ephemeral_public_key {
        return Err(
            "response attestation doc public_key does not match the response ephemeral key"
                .to_string(),
        );
    }
    if response.ephemeral_public_key != attested_ephemeral_key {
        println!(
            "note: a different replica answered the prove call; its ephemeral key is \
             authenticated by the response's own attestation doc"
        );
    }
    verify_attestation_doc_manifest_commitment(
        &response_doc,
        ManifestCommitmentKind::Live,
        &manifest_hash,
    )
    .map_err(|e| format!("response live manifest commitment verification failed: {e:?}"))?;
    println!(
        "ok: response quorum key == attested manifest quorum key; ephemeral key bound to the \
         same manifest via the response attestation doc (PCR{LIVE_MANIFEST_COMMITMENT_PCR_INDEX})"
    );
    verify_signature(
        &response.quorum_public_key,
        &response.quorum_key_signature,
        &signed_payload,
        "quorum_key_signature",
    )?;
    verify_signature(
        &response.ephemeral_public_key,
        &response.ephemeral_key_signature,
        &signed_payload,
        "ephemeral_key_signature",
    )?;
    println!(
        "ok: quorum + ephemeral signatures verify over the recomputed canonical QOS JSON \
         ({} bytes)",
        signed_payload.len()
    );

    Ok(response)
}
