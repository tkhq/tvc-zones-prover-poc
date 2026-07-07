//! Router for the zone prover REST server
use crate::handlers::{health, prove_zone_batch};
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
    use qos_p256::{P256Pair, P256Public};
    use tower::ServiceExt;

    async fn body_string(body: Body) -> String {
        let bytes = body
            .collect()
            .await
            .expect("failed to read body")
            .to_bytes();
        String::from_utf8(bytes.to_vec()).expect("invalid utf8")
    }

    fn router_with_generated_keys() -> Router {
        let ephemeral_key = P256Pair::generate().expect("failed to generate ephemeral key");
        let quorum_key = P256Pair::generate().expect("failed to generate quorum key");

        router_with_state(AppState::new(ephemeral_key, quorum_key))
    }

    #[tokio::test]
    async fn test_health() {
        let app = router_with_generated_keys();
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
    async fn prove_zone_batch_returns_verifiable_signatures() {
        let app = router_with_generated_keys();
        let witness = qos_hex::encode(b"test witness");
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/prove_zone_batch")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"witness":"{witness}"}}"#)))
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

        assert!(!hex_field("attestation_doc").is_empty());
        assert!(!hex_field("manifest").is_empty());
    }

    #[tokio::test]
    async fn prove_zone_batch_rejects_malformed_witness_hex() {
        let app = router_with_generated_keys();
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
