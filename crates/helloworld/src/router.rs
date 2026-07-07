//! Router for the zone prover REST server
use crate::handlers::{health, mock_attestation_prove_zone_batch, prove_zone_batch};
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
        .route("/prove_zone_batch", post(prove_zone_batch))
        .route(
            "/mock_attestation/prove_zone_batch",
            post(mock_attestation_prove_zone_batch),
        )
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
    use qos_nsm::mock::{MOCK_NSM_ATTESTATION_DOCUMENT, MockNsm};
    use qos_p256::{P256Pair, P256Public};
    use std::sync::Arc;
    use tower::ServiceExt;

    const FAKE_MANIFEST: &[u8] = b"fake-manifest-envelope";

    async fn body_string(body: Body) -> String {
        let bytes = body
            .collect()
            .await
            .expect("failed to read body")
            .to_bytes();
        String::from_utf8(bytes.to_vec()).expect("invalid utf8")
    }

    fn router_with_manifest_file(manifest_file: &str) -> Router {
        let ephemeral_key = P256Pair::generate().expect("failed to generate ephemeral key");
        let quorum_key = P256Pair::generate().expect("failed to generate quorum key");

        router_with_state(AppState::new(
            ephemeral_key,
            quorum_key,
            Arc::new(MockNsm),
            manifest_file,
        ))
    }

    fn router_with_generated_keys() -> (Router, tempfile::TempDir) {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let manifest_file = temp_dir.path().join("qos.manifest");
        std::fs::write(&manifest_file, FAKE_MANIFEST).expect("failed to write manifest");
        let app =
            router_with_manifest_file(manifest_file.to_str().expect("temp path should be utf8"));

        (app, temp_dir)
    }

    async fn prove_zone_batch_request(app: Router, uri: &str) -> axum::response::Response {
        let witness = qos_hex::encode(b"test witness");
        app.oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"witness":"{witness}"}}"#)))
                .expect("failed to build request"),
        )
        .await
        .expect("failed to execute request")
    }

    fn assert_prove_zone_batch_signatures(json: &serde_json::Value) {
        let hex_field = |field: &str| {
            qos_hex::decode(json[field].as_str().expect("field should be a string"))
                .expect("field should hex decode")
        };

        let batch_output = hex_field("batch_output");
        assert!(
            batch_output.ends_with(b"test witness"),
            "batch output should be derived from the witness"
        );

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
    }

    #[tokio::test]
    async fn test_health() {
        let (app, _temp_dir) = router_with_generated_keys();
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
    async fn mock_attestation_prove_zone_batch_returns_verifiable_signatures() {
        let (app, _temp_dir) = router_with_generated_keys();
        let response = prove_zone_batch_request(app, "/mock_attestation/prove_zone_batch").await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response.into_body()).await;
        let json: serde_json::Value =
            serde_json::from_str(&body).expect("response is not valid JSON");

        assert_prove_zone_batch_signatures(&json);
        assert_eq!(
            json["attestation_doc"],
            qos_hex::encode(b"stub-attestation-doc")
        );
        assert_eq!(json["manifest"], qos_hex::encode(b"stub-manifest"));
    }

    #[tokio::test]
    async fn prove_zone_batch_returns_nsm_attestation_doc_and_manifest() {
        let (app, _temp_dir) = router_with_generated_keys();
        let response = prove_zone_batch_request(app, "/prove_zone_batch").await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response.into_body()).await;
        let json: serde_json::Value =
            serde_json::from_str(&body).expect("response is not valid JSON");

        assert_prove_zone_batch_signatures(&json);
        assert_eq!(
            json["attestation_doc"],
            qos_hex::encode(MOCK_NSM_ATTESTATION_DOCUMENT)
        );
        assert_eq!(json["manifest"], qos_hex::encode(FAKE_MANIFEST));
    }

    #[tokio::test]
    async fn prove_zone_batch_errors_when_manifest_is_missing() {
        let app = router_with_manifest_file("/nonexistent/qos.manifest");
        let response = prove_zone_batch_request(app, "/prove_zone_batch").await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn prove_zone_batch_rejects_malformed_witness_hex() {
        let (app, _temp_dir) = router_with_generated_keys();
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/prove_zone_batch")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"witness":"not-hex"}"#))
                    .expect("failed to build request"),
            )
            .await
            .expect("failed to execute request");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
