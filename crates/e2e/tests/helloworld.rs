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
async fn test_prove_zone_batch_errors_outside_enclave() {
    async fn test(test_args: TestArgs) {
        let client = reqwest::Client::new();
        let witness = qos_hex::encode(b"e2e witness");
        let resp = client
            .post(format!("{}/prove_zone_batch", test_args.base_url))
            .json(&serde_json::json!({ "witness": witness }))
            .send()
            .await
            .unwrap();
        // The real endpoint needs the NSM and QOS manifest, which only exist
        // inside an enclave.
        assert_eq!(resp.status(), 500);
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn test_mock_attestation_prove_zone_batch() {
    async fn test(test_args: TestArgs) {
        let client = reqwest::Client::new();
        let witness = qos_hex::encode(b"e2e witness");
        let resp = client
            .post(format!(
                "{}/mock_attestation/prove_zone_batch",
                test_args.base_url
            ))
            .json(&serde_json::json!({ "witness": witness }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().await.unwrap();

        let hex_field = |field: &str| qos_hex::decode(json[field].as_str().unwrap()).unwrap();

        let batch_output = hex_field("batch_output");
        assert!(batch_output.ends_with(b"e2e witness"));

        for (public_key_field, signature_field) in [
            ("quorum_public_key", "quorum_key_signature"),
            ("ephemeral_public_key", "ephemeral_key_signature"),
        ] {
            let public_key = P256Public::from_bytes(&hex_field(public_key_field)).unwrap();
            public_key
                .verify(&batch_output, &hex_field(signature_field))
                .unwrap();
        }

        assert!(!hex_field("attestation_doc").is_empty());
        assert!(!hex_field("manifest").is_empty());
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
