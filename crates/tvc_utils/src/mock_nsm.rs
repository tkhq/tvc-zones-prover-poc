//! Mock NSM provider for local testing outside an enclave. Builds a
//! structurally real COSE Sign1 [`AttestationDoc`] per attestation request:
//! `user_data` and `public_key` echoed from the request, an all-zeros PCR
//! bank, and PCR17 ([`LIVE_MANIFEST_COMMITMENT_PCR_INDEX`]) extended to the
//! live manifest commitment a real QOS enclave would produce.
//!
//! The document is signed with a fixed, publicly known P-384 key over
//! placeholder certificates, so certificate chain verification against the
//! AWS Nitro root MUST fail for these documents. Everything else (COSE
//! decode, `user_data`, `public_key`, the PCR17 manifest commitment) can be
//! verified exactly as if the document came from a real enclave.
//!
//! DO NOT USE IN PRODUCTION - only for local testing where `/dev/nsm` is
//! not available.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_nitro_enclaves_cose::{
    CoseSign1,
    crypto::{Hash, MessageDigest, SignatureAlgorithm, SigningPrivateKey, SigningPublicKey},
    error::CoseError,
    header_map::HeaderMap,
};
use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
use p384::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::hazmat::{PrehashSigner as _, PrehashVerifier as _},
};
use qos_nsm::NsmProvider;
use qos_nsm::nitro::{
    ATTESTABLE_PCR_COUNT, LIVE_MANIFEST_COMMITMENT_PCR_INDEX, ManifestCommitmentKind,
    PCR_SHA384_LEN, expected_manifest_commitment_pcr,
};
use qos_nsm::types::{NsmErrorCode, NsmRequest, NsmResponse};
use serde_bytes::ByteBuf;

/// Fixed, publicly known P-384 signing secret for mock attestation
/// documents. Taken from the `aws-nitro-enclaves-cose` test suite. DO NOT
/// USE IN PRODUCTION.
const MOCK_P384_SECRET: [u8; 48] = [
    0x55, 0xc6, 0xaa, 0x81, 0x5a, 0x31, 0x74, 0x1b, 0xc3, 0x7f, 0x0f, 0xfd, 0xde, 0xa7, 0x3a, 0xf2,
    0x39, 0x7b, 0xad, 0x64, 0x08, 0x16, 0xef, 0x22, 0xbf, 0xb6, 0x89, 0xef, 0xc1, 0xb6, 0xcc, 0x68,
    0x2a, 0x73, 0xf7, 0xe5, 0xa6, 0x57, 0x24, 0x8e, 0x3a, 0xba, 0xd5, 0x00, 0xe4, 0x6d, 0x5a, 0xfc,
];

/// Placeholder end entity certificate embedded in mock attestation
/// documents. Not a real X.509 certificate: certificate chain verification
/// is expected to fail for mock documents.
const MOCK_CERTIFICATE: &[u8] = b"mock end entity certificate - not a real x509 cert";

/// Placeholder CA bundle entry embedded in mock attestation documents.
const MOCK_CA_BUNDLE: &[u8] = b"mock ca bundle - not a real x509 cert";

/// Mock NSM provider that builds real COSE Sign1 attestation documents with
/// the request's `user_data`/`public_key` and a correct QOS live manifest
/// commitment in PCR17.
///
/// DO NOT USE IN PRODUCTION - only for local testing where `/dev/nsm` is not
/// available.
#[derive(Debug)]
pub struct MockNsm {
    /// QOS manifest hash committed to in the live manifest-commitment PCR.
    manifest_hash: [u8; 32],
}

impl MockNsm {
    /// Create a mock NSM that commits to the given QOS manifest hash (the
    /// canonical QOS JSON hash of the v2 manifest) in the live
    /// manifest-commitment PCR.
    #[must_use]
    pub fn new(manifest_hash: [u8; 32]) -> Self {
        Self { manifest_hash }
    }

    fn attestation_doc(
        &self,
        user_data: Option<Vec<u8>>,
        public_key: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, MockNsmError> {
        let mut pcrs = BTreeMap::new();
        for index in 0..ATTESTABLE_PCR_COUNT {
            pcrs.insert(usize::from(index), ByteBuf::from(vec![0u8; PCR_SHA384_LEN]));
        }
        // Extend the live manifest commitment PCR exactly like a real QOS
        // enclave would for this manifest hash + ephemeral public key.
        if let Some(ephemeral_public_key) = &public_key {
            let pcr = expected_manifest_commitment_pcr(
                ManifestCommitmentKind::Live,
                &self.manifest_hash,
                ephemeral_public_key,
            )
            .map_err(|_| MockNsmError)?;
            pcrs.insert(
                usize::from(LIVE_MANIFEST_COMMITMENT_PCR_INDEX),
                ByteBuf::from(pcr.to_vec()),
            );
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MockNsmError)?
            .as_millis()
            .try_into()
            .map_err(|_| MockNsmError)?;

        let doc = AttestationDoc {
            module_id: "mock-nsm-module".to_string(),
            digest: Digest::SHA384,
            timestamp,
            pcrs,
            certificate: ByteBuf::from(MOCK_CERTIFICATE.to_vec()),
            cabundle: vec![ByteBuf::from(MOCK_CA_BUNDLE.to_vec())],
            public_key: public_key.map(ByteBuf::from),
            user_data: user_data.map(ByteBuf::from),
            nonce: None,
        };

        let signer = P384Signer::from_mock_secret()?;
        let cose_sign1 = CoseSign1::new::<Sha2>(&doc.to_binary(), &HeaderMap::new(), &signer)
            .map_err(|_| MockNsmError)?;
        cose_sign1.as_bytes(true).map_err(|_| MockNsmError)
    }
}

impl NsmProvider for MockNsm {
    fn nsm_process_request(&self, request: NsmRequest) -> NsmResponse {
        match request {
            NsmRequest::Attestation {
                user_data,
                nonce: _,
                public_key,
            } => match self.attestation_doc(user_data, public_key) {
                Ok(document) => NsmResponse::Attestation { document },
                Err(MockNsmError) => NsmResponse::Error(NsmErrorCode::InternalError),
            },
            _ => NsmResponse::Error(NsmErrorCode::InvalidOperation),
        }
    }

    fn timestamp_ms(&self) -> Result<u64, qos_nsm::nitro::AttestError> {
        Ok(0)
    }
}

/// Internal error building a mock attestation document.
struct MockNsmError;

struct P384Signer(SigningKey);

impl P384Signer {
    fn from_mock_secret() -> Result<Self, MockNsmError> {
        SigningKey::from_slice(&MOCK_P384_SECRET)
            .map(Self)
            .map_err(|_| MockNsmError)
    }
}

impl SigningPrivateKey for P384Signer {
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError> {
        self.0
            .sign_prehash(digest)
            .map(|sig: Signature| sig.to_vec())
            .map_err(|e| CoseError::SignatureError(Box::new(e)))
    }
}

impl SigningPublicKey for P384Signer {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        Ok((SignatureAlgorithm::ES384, MessageDigest::Sha384))
    }

    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        let signature =
            Signature::try_from(signature).map_err(|e| CoseError::SignatureError(Box::new(e)))?;
        VerifyingKey::from(&self.0)
            .verify_prehash(digest, &signature)
            .map(|()| true)
            .map_err(|e| CoseError::SignatureError(Box::new(e)))
    }
}

struct Sha2;

impl Hash for Sha2 {
    fn hash(digest: MessageDigest, data: &[u8]) -> Result<Vec<u8>, CoseError> {
        use sha2::Digest as _;
        match digest {
            MessageDigest::Sha256 => Ok(sha2::Sha256::digest(data).to_vec()),
            MessageDigest::Sha384 => Ok(sha2::Sha384::digest(data).to_vec()),
            MessageDigest::Sha512 => Ok(sha2::Sha512::digest(data).to_vec()),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use qos_nsm::nitro::{
        unsafe_attestation_doc_from_der, verify_attestation_doc_manifest_commitment,
    };

    #[test]
    fn mock_attestation_doc_round_trips_and_commits_to_manifest() {
        let manifest_hash = [7u8; 32];
        let user_data = b"fake batch output hash".to_vec();
        let ephemeral_public_key = vec![3u8; 65];

        let nsm = MockNsm::new(manifest_hash);
        let NsmResponse::Attestation { document } =
            nsm.nsm_process_request(NsmRequest::Attestation {
                user_data: Some(user_data.clone()),
                nonce: None,
                public_key: Some(ephemeral_public_key.clone()),
            })
        else {
            panic!("expected attestation response");
        };

        let doc = unsafe_attestation_doc_from_der(&document).unwrap();
        assert_eq!(doc.user_data.as_ref().unwrap().as_ref(), user_data);
        assert_eq!(
            doc.public_key.as_ref().unwrap().as_ref(),
            ephemeral_public_key
        );
        verify_attestation_doc_manifest_commitment(
            &doc,
            ManifestCommitmentKind::Live,
            &manifest_hash,
        )
        .unwrap();
    }

    #[test]
    fn mock_rejects_non_attestation_requests() {
        let nsm = MockNsm::new([0u8; 32]);
        let response = nsm.nsm_process_request(NsmRequest::DescribeNSM);
        assert!(matches!(response, NsmResponse::Error(_)));
    }
}
