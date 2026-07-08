//! Reference implementation of the ON-CHAIN VERIFIER role.
//!
//! What an on-chain verifier contract / precompile does with a prove
//! response, step by step:
//!
//! 0. Decode the `BatchOutput`, recompute its canonical QOS JSON encoding
//!    (`qos_json::to_vec` — the exact bytes the enclave signs), and verify
//!    the quorum and ephemeral signatures over those recomputed bytes.
//! 1. Decode the attestation document (COSE Sign1 -> `AttestationDoc`) and
//!    check `user_data == sha256(batch_output)` and that the doc's
//!    `public_key` is the ephemeral key that signed the batch output.
//! 2. Verify the certificate chain against the AWS Nitro root and the COSE
//!    Sign1 signature (`qos_nsm::nitro::attestation_doc_from_der`).
//! 3. Print PCR0/1/2/3 for comparison against known-good release values.
//! 4. Verify the QOS live manifest commitment: `hash(manifest)` (canonical
//!    QOS JSON hash) + the attested ephemeral key must extend to the value
//!    in PCR17 (`qos_nsm::nitro::LIVE_MANIFEST_COMMITMENT_PCR_INDEX`).
//! 5. Decode the manifest (JSON -> `ManifestEnvelopeV2`) and print its key
//!    fields, cross-checking the quorum key and the enclave PCRs.
//! 6. Print the manifest pivot (app) hash for comparison against a
//!    known-good reproducible build of the app.

use qos_core::protocol::services::boot::VersionedManifestEnvelope;
use qos_core::protocol::services::boot::manifest::canonical_json_hash;
use qos_nsm::nitro::{
    LIVE_MANIFEST_COMMITMENT_PCR_INDEX, ManifestCommitmentKind, unsafe_attestation_doc_from_der,
    verify_attestation_doc_manifest_commitment,
};
use sha2::Digest as _;
use zones_prover::ProveZoneBatchResponse;

use crate::attest::{doc_pcr, verify_attestation_doc_root, verify_signature};

/// Emulate what an ON-CHAIN VERIFIER contract / precompile does with a
/// prove response, step by step. See the module docs for the step list.
#[allow(clippy::too_many_lines)]
pub fn emulate_onchain_verifier(
    response: &ProveZoneBatchResponse,
    unsafe_skip_root_verification: bool,
) -> Result<(), String> {
    // Step 0: recompute the canonical signed bytes and verify the
    // signatures over exactly those bytes. The response carries the
    // BatchOutput as structured JSON, already decoded into the full Rust
    // type; the enclave signs its canonical QOS JSON encoding, so a
    // verifier re-encodes it canonically and never trusts unparsed bytes.
    println!("\nverifier step 0: recompute canonical batch output bytes and verify signatures");
    let batch_output = qos_json::to_vec(&response.batch_output)
        .map_err(|e| format!("failed to canonically serialize the batch output: {e}"))?;
    verify_signature(
        &response.quorum_public_key,
        &response.quorum_key_signature,
        &batch_output,
        "quorum_key_signature",
    )?;
    verify_signature(
        &response.ephemeral_public_key,
        &response.ephemeral_key_signature,
        &batch_output,
        "ephemeral_key_signature",
    )?;
    println!(
        "ok: quorum + ephemeral signatures verify over the recomputed canonical QOS JSON \
         ({} bytes)",
        batch_output.len()
    );

    // Step 1: decode the attestation document.
    println!("\nverifier step 1: decode attestation document (COSE Sign1 -> AttestationDoc)");
    let doc = unsafe_attestation_doc_from_der(&response.attestation_doc)
        .map_err(|e| format!("attestation_doc is not a COSE Sign1 attestation document: {e:?}"))?;
    let user_data = doc
        .user_data
        .as_ref()
        .ok_or("attestation doc has no user_data")?;
    // The one deviation from a standard QOS doc: user_data commits to the
    // batch output (as sha256, since the NSM caps user_data at 512 bytes)
    // instead of the manifest hash.
    if user_data.as_ref() != sha2::Sha256::digest(&batch_output).as_slice() {
        return Err(format!(
            "attestation user_data does not commit to the batch output:\n  user_data:              {}\n  sha256(batch_output):   {}",
            qos_hex::encode(user_data),
            qos_hex::encode(&sha2::Sha256::digest(&batch_output))
        ));
    }
    let doc_public_key = doc
        .public_key
        .as_ref()
        .ok_or("attestation doc has no public_key")?;
    if doc_public_key.as_ref() != response.ephemeral_public_key {
        return Err(
            "attestation doc public_key does not match the response's ephemeral public key"
                .to_string(),
        );
    }
    println!("ok: user_data == sha256(batch_output); public_key == the signing ephemeral key");

    // Step 2: verify the certificate chain against the AWS Nitro root and
    // the COSE Sign1 signature.
    println!("\nverifier step 2: verify certificate chain against the AWS Nitro root");
    verify_attestation_doc_root(&response.attestation_doc, unsafe_skip_root_verification)?;

    // Step 3: print the platform PCRs.
    println!(
        "\nverifier step 3: enclave platform PCRs (compare against known-good release values)"
    );
    let pcr0 = doc_pcr(&doc, 0)?;
    let pcr1 = doc_pcr(&doc, 1)?;
    let pcr2 = doc_pcr(&doc, 2)?;
    let pcr3 = doc_pcr(&doc, 3)?;
    println!("  PCR0 (enclave image):    {}", qos_hex::encode(&pcr0));
    println!("  PCR1 (kernel/bootstrap): {}", qos_hex::encode(&pcr1));
    println!("  PCR2 (application):      {}", qos_hex::encode(&pcr2));
    println!("  PCR3 (IAM role):         {}", qos_hex::encode(&pcr3));

    // Step 4: verify the QOS live manifest commitment in PCR17.
    println!(
        "\nverifier step 4: verify manifest commitment PCR (hash(manifest) + ephemeral key -> PCR{LIVE_MANIFEST_COMMITMENT_PCR_INDEX})"
    );
    // The manifest arrives as structured JSON, already decoded into the
    // full manifest envelope type: recompute the attested hash locally.
    let VersionedManifestEnvelope::V2(envelope) = &response.manifest else {
        return Err("manifest is not a v2 manifest envelope".to_string());
    };
    let manifest_hash = canonical_json_hash(&envelope.manifest);
    // Note: qos 0.12 uses PCR16 for the setup/boot commitment and PCR17 for
    // the live/app commitment; a running app attests the live one.
    verify_attestation_doc_manifest_commitment(&doc, ManifestCommitmentKind::Live, &manifest_hash)
        .map_err(|e| format!("live manifest commitment verification failed: {e:?}"))?;
    println!(
        "ok: PCR{LIVE_MANIFEST_COMMITMENT_PCR_INDEX} == SHA384-extend of the domain-separated \
         (manifest hash, ephemeral key) commitment"
    );

    // Step 5: decode the manifest and print its key fields.
    println!("\nverifier step 5: decode manifest (JSON -> ManifestEnvelopeV2)");
    let manifest = &envelope.manifest;
    println!("  namespace: {}", manifest.namespace.name);
    println!(
        "  approvals: {} of {} manifest set, {} of {} share set",
        envelope.manifest_set_approvals.len(),
        manifest.manifest_set.members.len(),
        envelope.share_set_approvals.len(),
        manifest.share_set.members.len()
    );
    if manifest.namespace.quorum_key != response.quorum_public_key {
        return Err(format!(
            "manifest quorum key does not match the quorum key that signed the batch output:\n  manifest: {}\n  response: {}",
            qos_hex::encode(&manifest.namespace.quorum_key),
            qos_hex::encode(&response.quorum_public_key)
        ));
    }
    println!("ok: manifest quorum key == quorum key that signed the batch output");
    for (index, doc_value, manifest_value) in [
        (0u16, &pcr0, &manifest.enclave.pcr0),
        (1, &pcr1, &manifest.enclave.pcr1),
        (2, &pcr2, &manifest.enclave.pcr2),
        (3, &pcr3, &manifest.enclave.pcr3),
    ] {
        if doc_value != manifest_value {
            return Err(format!(
                "attestation doc PCR{index} does not match the manifest's expected value:\n  doc:      {}\n  manifest: {}",
                qos_hex::encode(doc_value),
                qos_hex::encode(manifest_value)
            ));
        }
    }
    println!("ok: attestation doc PCR0/1/2/3 match the manifest's expected enclave PCRs");

    // Step 6: the pivot (app) hash, to compare against the known-good hash
    // of the reproducibly built zones_prover app binary (the stagex build).
    println!("\nverifier step 6: manifest pivot (app) hash");
    println!("  pivot hash: {}", qos_hex::encode(&manifest.pivot.hash));

    Ok(())
}
