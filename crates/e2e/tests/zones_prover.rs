#![allow(missing_docs, clippy::unwrap_used)]

use e2e::TestArgs;
use qos_p256::P256Public;

#[tokio::test]
async fn test_health() {
    async fn test(test_args: TestArgs) {
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/health", test_args.base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(json["status"], "healthy");
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn test_enclave_identity() {
    async fn test(test_args: TestArgs) {
        use qos_core::protocol::services::boot::manifest::canonical_json_hash;

        let client = reqwest::Client::new();
        let identity: serde_json::Value = client
            .get(format!("{}/enclave_identity", test_args.base_url))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        let hex_field = |field: &str| qos_hex::decode(identity[field].as_str().unwrap()).unwrap();

        // The manifest is returned as structured JSON: decode it into the
        // full ManifestEnvelopeV2 and check it matches the on-disk envelope.
        let envelope: qos_core::protocol::services::boot::ManifestEnvelopeV2 =
            serde_json::from_value(identity["manifest"].clone()).unwrap();
        let expected_envelope: qos_core::protocol::services::boot::ManifestEnvelopeV2 =
            serde_json::from_slice(&test_args.manifest).unwrap();
        assert_eq!(envelope, expected_envelope);
        let manifest_hash = canonical_json_hash(&envelope.manifest);
        assert_eq!(
            envelope.manifest.namespace.quorum_key,
            hex_field("quorum_public_key"),
        );

        // Fresh identity attestation doc: manifest hash in user_data (QOS
        // convention), PCR17 commitment.
        let doc =
            qos_nsm::nitro::unsafe_attestation_doc_from_der(&hex_field("attestation_doc")).unwrap();
        assert_eq!(doc.user_data.as_ref().unwrap().as_ref(), manifest_hash);
        assert_eq!(
            doc.public_key.as_ref().unwrap().as_ref(),
            hex_field("ephemeral_public_key"),
        );
        qos_nsm::nitro::verify_attestation_doc_manifest_commitment(
            &doc,
            qos_nsm::nitro::ManifestCommitmentKind::Live,
            &manifest_hash,
        )
        .unwrap();
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn test_prove_zone_batch() {
    async fn test(test_args: TestArgs) {
        let client = reqwest::Client::new();
        let witness = tempo_zones_stubs::fixtures::example_witness();
        let expected_output = tempo_zones_stubs::prover::prove_zone_batch(&witness).unwrap();

        // Fetch the enclave identity and encrypt the witness to the
        // quorum key.
        let identity: serde_json::Value = client
            .get(format!("{}/enclave_identity", test_args.base_url))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let quorum_public = P256Public::from_bytes(
            &qos_hex::decode(identity["quorum_public_key"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let encrypted_witness = quorum_public
            .encrypt(&serde_json::to_vec(&witness).unwrap())
            .unwrap();

        let resp = client
            .post(format!("{}/prove_zone_batch", test_args.base_url))
            .json(&serde_json::json!({ "encrypted_witness": qos_hex::encode(&encrypted_witness) }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().await.unwrap();

        let hex_field = |field: &str| qos_hex::decode(json[field].as_str().unwrap()).unwrap();

        // The batch output is returned as structured JSON; the signed bytes
        // are its canonical QOS JSON encoding, recomputed locally.
        let output: tempo_zones_stubs::BatchOutput =
            serde_json::from_value(json["batch_output"].clone()).unwrap();
        assert_eq!(output, expected_output);
        let batch_output = qos_json::to_vec(&output).unwrap();

        for (public_key_field, signature_field) in [
            ("quorum_public_key", "quorum_key_signature"),
            ("ephemeral_public_key", "ephemeral_key_signature"),
        ] {
            let public_key = P256Public::from_bytes(&hex_field(public_key_field)).unwrap();
            public_key
                .verify(&batch_output, &hex_field(signature_field))
                .unwrap();
        }

        // The attestation doc is a real COSE Sign1 document built by the
        // NSM. It must bind sha256(batch_output) via `user_data` and
        // commit to the manifest hash via the live manifest-commitment
        // PCR.
        use qos_core::protocol::services::boot::manifest::canonical_json_hash;
        use sha2::Digest as _;
        let doc =
            qos_nsm::nitro::unsafe_attestation_doc_from_der(&hex_field("attestation_doc")).unwrap();
        assert_eq!(
            doc.user_data.as_ref().unwrap().as_ref(),
            sha2::Sha256::digest(&batch_output).as_slice(),
            "attestation user_data should be sha256 of the canonical batch output bytes"
        );
        assert_eq!(
            doc.public_key.as_ref().unwrap().as_ref(),
            hex_field("ephemeral_public_key"),
            "attestation public_key should be the ephemeral public key"
        );
        let envelope: qos_core::protocol::services::boot::ManifestEnvelopeV2 =
            serde_json::from_slice(&test_args.manifest).unwrap();
        qos_nsm::nitro::verify_attestation_doc_manifest_commitment(
            &doc,
            qos_nsm::nitro::ManifestCommitmentKind::Live,
            &canonical_json_hash(&envelope.manifest),
        )
        .unwrap();

        let response_envelope: qos_core::protocol::services::boot::ManifestEnvelopeV2 =
            serde_json::from_value(json["manifest"].clone()).unwrap();
        assert_eq!(response_envelope, envelope);
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn test_metrics() {
    async fn test(test_args: TestArgs) {
        let client = reqwest::Client::new();

        // Hit an endpoint first so the histogram has data
        client
            .get(format!("{}/health", test_args.base_url))
            .send()
            .await
            .unwrap();

        let resp = client
            .get(format!("{}/metrics", test_args.base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let content_type = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            content_type.starts_with("text/plain"),
            "expected prometheus text format content type, got: {content_type}"
        );

        let body = resp.text().await.unwrap();
        assert!(
            body.contains("tvc_http_request_duration_ms"),
            "should contain the namespaced histogram metric"
        );
        assert!(
            body.contains("method=\"GET\""),
            "should contain method label"
        );
    }
    e2e::Builder::new().execute(test).await;
}

/// The server must fail fast at startup (before binding) when the manifest
/// file is missing, instead of serving requests that 500 on every call.
#[test]
fn test_startup_fails_when_manifest_is_missing() {
    use qos_p256::P256Pair;

    let temp_dir = tempfile::tempdir().unwrap();
    let ephemeral_key_path = temp_dir.path().join("qos.ephemeral.key");
    let quorum_key_path = temp_dir.path().join("qos.quorum.key");
    P256Pair::generate()
        .unwrap()
        .to_hex_file(&ephemeral_key_path)
        .unwrap();
    P256Pair::generate()
        .unwrap()
        .to_hex_file(&quorum_key_path)
        .unwrap();
    let missing_manifest = temp_dir.path().join("nonexistent.manifest");

    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin("zones_prover"))
        .arg("--host")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(e2e::find_free_port().unwrap().to_string())
        .arg("--ephemeral-file")
        .arg(&ephemeral_key_path)
        .arg("--quorum-file")
        .arg(&quorum_key_path)
        .arg("--manifest-file")
        .arg(&missing_manifest)
        .arg("--mock-nsm")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "server should exit with an error when the manifest is missing"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to read manifest file"),
        "stderr should explain the missing manifest, got: {stderr}"
    );
    assert!(
        stderr.contains(missing_manifest.to_str().unwrap()),
        "stderr should include the manifest path, got: {stderr}"
    );
}
