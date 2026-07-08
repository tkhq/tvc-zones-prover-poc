//! Fake QOS manifest envelope for local testing: a structurally valid
//! [`ManifestEnvelopeV2`] (real deployments get one from the QOS boot flow)
//! so verifiers can exercise the manifest decode + PCR17 commitment path
//! locally. All values (pivot hash, PCRs, set members) are placeholders.

use qos_core::protocol::services::boot::{
    ManifestEnvelopeV2, ManifestSet, ManifestV2, ManifestVersion, Namespace, NitroConfig,
    PivotConfigV2, PivotEnv, QuorumMember, RestartPolicy, ShareSet,
};
use qos_nsm::nitro::{AWS_ROOT_CERT_PEM, PCR_SHA384_LEN, cert_from_pem};
use sha2::Digest as _;

/// Build a fake but structurally valid [`ManifestEnvelopeV2`] for local
/// testing, embedding the given quorum public key (P256 sec1 bytes) in the
/// namespace so verifiers can cross-check it against the quorum key that
/// signs responses.
#[must_use]
pub fn fake_manifest_envelope(quorum_public_key: &[u8]) -> ManifestEnvelopeV2 {
    let member = QuorumMember {
        alias: "local-mock".to_string(),
        pub_key: quorum_public_key.to_vec(),
    };

    ManifestEnvelopeV2 {
        manifest: ManifestV2 {
            version: ManifestVersion::V2,
            namespace: Namespace {
                name: "tvc-zones-prover-local".to_string(),
                nonce: 1,
                quorum_key: quorum_public_key.to_vec(),
            },
            pivot: PivotConfigV2 {
                hash: sha2::Sha256::digest(b"tvc-zones-prover-fake-pivot").into(),
                restart: RestartPolicy::Never,
                bridge_config: Vec::new(),
                debug_mode: false,
                args: Vec::new(),
                env: PivotEnv::new(),
            },
            manifest_set: ManifestSet {
                threshold: 1,
                members: vec![member.clone()],
            },
            share_set: ShareSet {
                threshold: 1,
                members: vec![member],
            },
            enclave: NitroConfig {
                pcr0: vec![0u8; PCR_SHA384_LEN],
                pcr1: vec![0u8; PCR_SHA384_LEN],
                pcr2: vec![0u8; PCR_SHA384_LEN],
                pcr3: vec![0u8; PCR_SHA384_LEN],
                aws_root_certificate: cert_from_pem(AWS_ROOT_CERT_PEM).unwrap_or_default(),
                qos_commit: "mock".to_string(),
            },
            dns: None,
        },
        manifest_set_approvals: Vec::new(),
        share_set_approvals: Vec::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn fake_manifest_envelope_round_trips_through_json() {
        let envelope = fake_manifest_envelope(&[9u8; 65]);
        let bytes = qos_json::to_vec(&envelope).unwrap();
        let decoded: ManifestEnvelopeV2 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.manifest.namespace.quorum_key, vec![9u8; 65]);
        assert_eq!(decoded.manifest.version, ManifestVersion::V2);
    }
}
