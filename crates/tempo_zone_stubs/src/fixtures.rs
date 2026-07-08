//! Test fixtures for the tempo zone batch types.
//!
//! Unlike the rest of this crate, this module is NOT expected to come from
//! the tempo repo: it is PoC-local fake data for tests and the
//! `tvc_zones_cli` demo flow, gated behind the `fixtures` feature.

use crate::alloy_primitives::keccak256;
use crate::zone_primitives::constants::{
    PORTAL_SEQUENCER_SLOT, ZONE_INBOX_ADDRESS, ZONE_INBOX_PROCESSED_HASH_SLOT,
};
use crate::{
    Address, B256, BatchStateProof, BatchWitness, Bytes, DepositType, EnabledToken, L1StateRead,
    PublicInputs, QueuedDeposit, U256, ZoneAccountRead, ZoneBlock, ZoneHeader, ZoneStateWitness,
    ZoneStorageRead,
};

/// Build a well-formed fake [`BatchWitness`] for local testing: one zone
/// block with a regular deposit and a withdrawal batch finalization,
/// consistent with the structural invariants checked by
/// [`crate::prover::prove_zone_batch`].
///
/// `prev_block_hash` is derived from the previous header with the real
/// `zone-primitives` block-hash rule, and the state reads target the real
/// protocol storage slots from `zone_primitives::constants`.
#[must_use]
pub fn example_witness() -> BatchWitness {
    let sequencer = Address::repeat_byte(0x5e);

    let prev_block_header = ZoneHeader {
        parent_hash: B256::repeat_byte(0x10),
        beneficiary: sequencer,
        state_root: B256::repeat_byte(0x33),
        transactions_root: B256::repeat_byte(0x44),
        receipts_root: B256::repeat_byte(0x55),
        number: 41,
        timestamp: 1_700_000_000,
        protocol_version: 1,
    };
    // The previous batch's block hash per the spec's block-hash rule.
    let prev_block_hash = prev_block_header.hash();

    BatchWitness {
        public_inputs: PublicInputs {
            prev_block_hash,
            tempo_block_number: 100,
            anchor_block_number: 100,
            anchor_block_hash: B256::repeat_byte(0x22),
            expected_withdrawal_batch_index: 7,
            sequencer,
        },
        prev_block_header,
        zone_blocks: vec![ZoneBlock {
            number: 42,
            parent_hash: prev_block_hash,
            timestamp: 1_700_000_012,
            beneficiary: sequencer,
            protocol_version: 1,
            tempo_header_rlp: Some(Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef])),
            deposits: vec![QueuedDeposit {
                deposit_type: DepositType::Regular,
                deposit_data: Bytes::from_static(&[0x01, 0x02, 0x03]),
                rejected: false,
            }],
            decryptions: Vec::new(),
            enabled_tokens: vec![EnabledToken {
                token: Address::repeat_byte(0x70),
                name: "Fake Token".to_string(),
                symbol: "FAKE".to_string(),
                currency: "USD".to_string(),
            }],
            finalize_withdrawal_batch_count: Some(U256::from(1u64)),
            finalize_withdrawal_batch_encrypted_senders: vec![Bytes::new()],
            transactions: vec![Bytes::from_static(&[0xca, 0xfe])],
        }],
        initial_zone_state: ZoneStateWitness {
            state_root: B256::repeat_byte(0x33),
            node_pool: std::collections::HashMap::new(),
            account_reads: vec![ZoneAccountRead {
                account: sequencer,
                nonce: 3,
                balance: U256::from(1_000_000u64),
                code_hash: keccak256([]),
                code: None,
            }],
            // Zone-state read of the ZoneInbox's processed deposit queue
            // hash, at the real predeploy address and storage slot.
            storage_reads: vec![ZoneStorageRead {
                account: ZONE_INBOX_ADDRESS,
                slot: ZONE_INBOX_PROCESSED_HASH_SLOT,
                value: U256::from(99u64),
            }],
        },
        tempo_state_proofs: BatchStateProof {
            node_pool: std::collections::HashMap::new(),
            // Tempo read of the ZonePortal's registered sequencer (portal
            // storage slot 0), as the proof system does to check the
            // beneficiary.
            reads: vec![L1StateRead {
                zone_block_index: 0,
                tempo_block_number: 100,
                account: Address::repeat_byte(0x80),
                slot: U256::from_be_bytes(PORTAL_SEQUENCER_SLOT.0),
                value: U256::from_be_slice(sequencer.as_slice()),
            }],
        },
        tempo_ancestry_headers: Vec::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn example_witness_prev_hash_uses_spec_block_hash_rule() {
        let witness = example_witness();
        assert_eq!(
            witness.public_inputs.prev_block_hash,
            witness.prev_block_header.hash()
        );
    }

    #[test]
    fn byte_fields_serialize_as_0x_hex() {
        let witness = example_witness();
        let json = serde_json::to_value(&witness).unwrap();
        assert_eq!(
            json["zone_blocks"][0]["tempo_header_rlp"],
            serde_json::json!("0xdeadbeef")
        );
        assert_eq!(
            json["zone_blocks"][0]["deposits"][0]["deposit_data"],
            serde_json::json!("0x010203")
        );
        assert_eq!(
            json["zone_blocks"][0]["transactions"],
            serde_json::json!(["0xcafe"])
        );
    }
}
