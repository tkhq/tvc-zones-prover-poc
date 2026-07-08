//! Router for the zone prover REST server
use crate::handlers::{enclave_identity, health, prove_zone_batch};
use axum::{
    Router,
    routing::{get, post},
};
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;

pub use crate::state::AppState;

/// Build the application router with the given state.
pub fn router_with_state(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/enclave_identity", get(enclave_identity))
        .route("/prove_zone_batch", post(prove_zone_batch))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::StatusCode;
    use http_body_util::BodyExt;
    use qos_core::protocol::services::boot::manifest::canonical_json_hash;
    use qos_nsm::nitro::{
        ManifestCommitmentKind, unsafe_attestation_doc_from_der,
        verify_attestation_doc_manifest_commitment,
    };
    use qos_p256::{P256Pair, P256Public};
    use sha2::Digest as _;
    use std::sync::Arc;
    use tempo_zones_stubs::fixtures::example_witness;
    use tempo_zones_stubs::{BatchOutput, prover::prove_zone_batch};
    use tower::ServiceExt;
    use tvc_utils::fake_manifest::fake_manifest_envelope;
    use tvc_utils::mock_nsm::MockNsm;

    async fn body_string(body: Body) -> String {
        let bytes = body
            .collect()
            .await
            .expect("failed to read body")
            .to_bytes();
        String::from_utf8(bytes.to_vec()).expect("invalid utf8")
    }

    struct TestRouter {
        app: Router,
        /// JSON encoded v2 manifest envelope served by the router (whose
        /// hash the NSM commits to in PCR17).
        manifest: Vec<u8>,
        /// Quorum public key witnesses must be encrypted to.
        quorum_public: P256Public,
    }

    fn router_with_generated_keys() -> TestRouter {
        let ephemeral_key = P256Pair::generate().expect("failed to generate ephemeral key");
        let quorum_key = P256Pair::generate().expect("failed to generate quorum key");
        let quorum_public = P256Public::from_bytes(&quorum_key.public_key().to_bytes())
            .expect("failed to parse quorum public key");
        let envelope = qos_core::protocol::services::boot::VersionedManifestEnvelope::V2(
            fake_manifest_envelope(&quorum_key.public_key().to_bytes()),
        );
        let manifest = envelope
            .to_storage_vec()
            .expect("failed to serialize manifest envelope");

        let app = router_with_state(AppState::new(
            ephemeral_key,
            quorum_key,
            Arc::new(MockNsm::new(envelope.manifest_hash())),
            envelope,
        ));
        TestRouter {
            app,
            manifest,
            quorum_public,
        }
    }

    /// Encrypt the given witness to the quorum key and return the
    /// request body.
    fn encrypted_witness_body(
        witness: &tempo_zones_stubs::BatchWitness,
        quorum_public: &P256Public,
    ) -> String {
        let witness_json = serde_json::to_vec(witness).expect("witness should serialize");
        let encrypted = quorum_public
            .encrypt(&witness_json)
            .expect("witness should encrypt");
        serde_json::json!({ "encrypted_witness": qos_hex::encode(&encrypted) }).to_string()
    }

    async fn post_prove_zone_batch(app: Router, body: String) -> axum::response::Response {
        app.oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/prove_zone_batch")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("failed to build request"),
        )
        .await
        .expect("failed to execute request")
    }

    async fn prove_zone_batch_request(test_router: TestRouter) -> axum::response::Response {
        let body = encrypted_witness_body(&example_witness(), &test_router.quorum_public);
        post_prove_zone_batch(test_router.app, body).await
    }

    /// Decode the structured batch_output, re-serialize it to canonical QOS
    /// JSON, verify both signatures over the recomputed bytes, and return
    /// the signing payload.
    fn assert_prove_zone_batch_signatures(json: &serde_json::Value) -> Vec<u8> {
        let hex_field = |field: &str| {
            qos_hex::decode(json[field].as_str().expect("field should be a string"))
                .expect("field should hex decode")
        };

        // The batch output is the structured JSON BatchOutput for the
        // example witness; the signatures are over its canonical QOS JSON
        // encoding, recomputed locally.
        let output: BatchOutput = serde_json::from_value(json["batch_output"].clone())
            .expect("batch output should parse");
        let expected = prove_zone_batch(&example_witness()).expect("example witness should prove");
        assert_eq!(output, expected, "batch output should match the witness");
        let batch_output = qos_json::to_vec(&output).expect("batch output should serialize");

        for (public_key_field, signature_field) in [
            ("quorum_public_key", "quorum_key_signature"),
            ("ephemeral_public_key", "ephemeral_key_signature"),
        ] {
            let public_key = P256Public::from_bytes(&hex_field(public_key_field))
                .expect("public key should decode");
            public_key
                .verify(&batch_output, &hex_field(signature_field))
                .expect("signature should verify over the batch output");
        }
        batch_output
    }

    #[tokio::test]
    async fn test_health() {
        let TestRouter { app, .. } = router_with_generated_keys();
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("failed to build request"),
            )
            .await
            .expect("failed to execute request");

        assert_eq!(response.status(), 200);
        let body = body_string(response.into_body()).await;
        let json: serde_json::Value =
            serde_json::from_str(&body).expect("response is not valid JSON");
        assert_eq!(json["status"], "healthy");
    }

    #[tokio::test]
    async fn enclave_identity_returns_manifest_keys_and_fresh_attestation_doc() {
        let TestRouter { app, manifest, .. } = router_with_generated_keys();
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/enclave_identity")
                    .body(Body::empty())
                    .expect("failed to build request"),
            )
            .await
            .expect("failed to execute request");

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response.into_body()).await;
        let json: serde_json::Value =
            serde_json::from_str(&body).expect("response is not valid JSON");

        let hex_field = |field: &str| {
            qos_hex::decode(json[field].as_str().expect("field should be a string"))
                .expect("field should hex decode")
        };

        // The manifest is returned as structured JSON: decode it into the
        // full ManifestEnvelopeV2 and check it matches the served envelope.
        let envelope: qos_core::protocol::services::boot::ManifestEnvelopeV2 =
            serde_json::from_value(json["manifest"].clone())
                .expect("manifest envelope should decode");
        let expected_envelope: qos_core::protocol::services::boot::ManifestEnvelopeV2 =
            serde_json::from_slice(&manifest).expect("served manifest envelope should decode");
        assert_eq!(envelope, expected_envelope);
        let manifest_hash = canonical_json_hash(&envelope.manifest);
        assert_eq!(
            envelope.manifest.namespace.quorum_key,
            hex_field("quorum_public_key"),
            "manifest quorum key should match the served quorum public key"
        );

        // Fresh attestation doc: manifest hash in user_data (QOS
        // convention), live manifest commitment in PCR17.
        let doc = unsafe_attestation_doc_from_der(&hex_field("attestation_doc"))
            .expect("attestation doc should decode");
        assert_eq!(
            doc.user_data.as_ref().expect("user_data present").as_ref(),
            manifest_hash,
            "identity attestation user_data should be the manifest hash"
        );
        assert_eq!(
            doc.public_key
                .as_ref()
                .expect("public_key present")
                .as_ref(),
            hex_field("ephemeral_public_key"),
            "identity attestation public_key should be the ephemeral public key"
        );
        verify_attestation_doc_manifest_commitment(
            &doc,
            ManifestCommitmentKind::Live,
            &manifest_hash,
        )
        .expect("live manifest commitment should verify");
    }

    #[tokio::test]
    async fn prove_zone_batch_returns_attestation_doc_with_user_data_and_manifest() {
        let test_router = router_with_generated_keys();
        let manifest = test_router.manifest.clone();
        let response = prove_zone_batch_request(test_router).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response.into_body()).await;
        let json: serde_json::Value =
            serde_json::from_str(&body).expect("response is not valid JSON");

        let batch_output = assert_prove_zone_batch_signatures(&json);

        let hex_field = |field: &str| {
            qos_hex::decode(json[field].as_str().expect("field should be a string"))
                .expect("field should hex decode")
        };

        // The attestation doc is a real COSE Sign1 document binding
        // sha256(batch_output) via `user_data`.
        let doc = unsafe_attestation_doc_from_der(&hex_field("attestation_doc"))
            .expect("attestation doc should decode");
        assert_eq!(
            doc.user_data.as_ref().expect("user_data present").as_ref(),
            sha2::Sha256::digest(&batch_output).as_slice(),
            "attestation user_data should be sha256 of the canonical batch output bytes"
        );
        assert_eq!(
            doc.public_key
                .as_ref()
                .expect("public_key present")
                .as_ref(),
            hex_field("ephemeral_public_key"),
            "attestation public_key should be the ephemeral public key"
        );

        // PCR17 must carry the live manifest commitment for the served
        // manifest and the attested ephemeral key.
        let envelope: qos_core::protocol::services::boot::ManifestEnvelopeV2 =
            serde_json::from_slice(&manifest).expect("manifest envelope should decode");
        verify_attestation_doc_manifest_commitment(
            &doc,
            ManifestCommitmentKind::Live,
            &canonical_json_hash(&envelope.manifest),
        )
        .expect("live manifest commitment should verify");

        let response_envelope: qos_core::protocol::services::boot::ManifestEnvelopeV2 =
            serde_json::from_value(json["manifest"].clone())
                .expect("manifest envelope should decode");
        assert_eq!(response_envelope, envelope);
    }

    #[tokio::test]
    async fn prove_zone_batch_rejects_malformed_request() {
        let TestRouter { app, .. } = router_with_generated_keys();
        // Not hex at all -> rejected by request deserialization.
        let response = post_prove_zone_batch(
            app,
            r#"{"encrypted_witness":"not-hex-ciphertext"}"#.to_string(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn prove_zone_batch_rejects_undecryptable_witness() {
        let TestRouter { app, .. } = router_with_generated_keys();
        // Valid hex, but not a qos_p256 envelope for the ephemeral key.
        let body =
            serde_json::json!({ "encrypted_witness": qos_hex::encode(&[0xde, 0xad, 0xbe, 0xef]) })
                .to_string();
        let response = post_prove_zone_batch(app, body).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn prove_zone_batch_rejects_witness_encrypted_to_wrong_key() {
        let TestRouter { app, .. } = router_with_generated_keys();
        let wrong_key = P256Pair::generate().expect("failed to generate key");
        let wrong_public = P256Public::from_bytes(&wrong_key.public_key().to_bytes())
            .expect("failed to parse public key");
        let body = encrypted_witness_body(&example_witness(), &wrong_public);
        let response = post_prove_zone_batch(app, body).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn prove_zone_batch_rejects_invalid_witness_invariants() {
        let TestRouter {
            app,
            quorum_public,
            ..
        } = router_with_generated_keys();
        let mut witness = example_witness();
        witness.zone_blocks.clear();
        let body = encrypted_witness_body(&witness, &quorum_public);
        let response = post_prove_zone_batch(app, body).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
