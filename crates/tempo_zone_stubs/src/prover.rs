//! (Stubbed) zone proving function over the tempo zone batch types.
//!
//! The spec's stateless execution function (`specs/spec.md`, "Proving
//! System") is expected to eventually come from the tempo repo. Until then
//! this stub validates structural invariants of the witness and derives
//! placeholder commitments; the input/output shapes are the real ones.

use crate::alloy_primitives::keccak256;
use crate::{
    B256, BatchOutput, BatchWitness, BlockTransition, DepositQueueTransition, LastBatchCommitment,
    ZoneHeader,
};

/// Errors returned by [`prove_zone_batch`].
#[derive(Debug, thiserror::Error)]
pub enum ZoneProverError {
    /// The witness contains no zone blocks.
    #[error("witness contains no zone blocks")]
    EmptyBatch,
    /// A zone block's beneficiary does not match the registered sequencer.
    #[error("zone block {number} beneficiary does not match the sequencer")]
    BeneficiaryMismatch {
        /// Offending block number.
        number: u64,
    },
    /// Zone block numbers are not consecutive from the previous header.
    #[error("zone block numbers are not consecutive: expected {expected}, got {got}")]
    NonConsecutiveBlocks {
        /// Expected block number.
        expected: u64,
        /// Actual block number.
        got: u64,
    },
    /// The first zone block's parent hash does not match the previous batch
    /// block hash.
    #[error("first zone block parent hash does not match prev_block_hash")]
    ParentHashMismatch,
}

/// Run the (stubbed) zone prover over the given witness.
///
/// Validates basic structural invariants of the witness, then derives
/// placeholder commitments. A real implementation would re-execute the zone
/// blocks per the tempo zones spec's stateless execution function.
///
/// # Errors
///
/// Returns [`ZoneProverError`] if the witness violates a structural
/// invariant.
pub fn prove_zone_batch(witness: &BatchWitness) -> Result<BatchOutput, ZoneProverError> {
    let Some(last_block) = witness.zone_blocks.last() else {
        return Err(ZoneProverError::EmptyBatch);
    };

    let mut expected_number = witness.prev_block_header.number.wrapping_add(1);
    for block in &witness.zone_blocks {
        if block.beneficiary != witness.public_inputs.sequencer {
            return Err(ZoneProverError::BeneficiaryMismatch {
                number: block.number,
            });
        }
        if block.number != expected_number {
            return Err(ZoneProverError::NonConsecutiveBlocks {
                expected: expected_number,
                got: block.number,
            });
        }
        expected_number = expected_number.wrapping_add(1);
    }

    if witness.zone_blocks[0].parent_hash != witness.public_inputs.prev_block_hash {
        return Err(ZoneProverError::ParentHashMismatch);
    }

    // Stub next block hash: build the last zone block's header and hash it
    // with the spec's block-hash rule from `zone-primitives`
    // (`keccak256(rlp_encode(header))`). The roots are placeholders carried
    // over from the witness; a real prover derives them from execution.
    let next_header = ZoneHeader {
        parent_hash: last_block.parent_hash,
        beneficiary: last_block.beneficiary,
        state_root: witness.initial_zone_state.state_root,
        transactions_root: witness.prev_block_header.transactions_root,
        receipts_root: witness.prev_block_header.receipts_root,
        number: last_block.number,
        timestamp: last_block.timestamp,
        protocol_version: last_block.protocol_version,
    };
    let next_block_hash = next_header.hash();

    // Stub deposit queue transition: fold every processed deposit into a
    // hash chain starting from the previous block hash.
    let prev_processed_hash = keccak256(witness.public_inputs.prev_block_hash);
    let mut next_processed_hash = prev_processed_hash;
    let mut deposit_count: u64 = 0;
    for block in &witness.zone_blocks {
        for deposit in &block.deposits {
            next_processed_hash =
                keccak256([next_processed_hash.as_slice(), &deposit.deposit_data].concat());
            deposit_count += 1;
        }
    }
    let prev_deposit_number = witness.public_inputs.tempo_block_number;
    let deposit_queue_transition = DepositQueueTransition {
        prev_processed_hash,
        next_processed_hash,
        prev_deposit_number,
        next_deposit_number: prev_deposit_number + deposit_count,
    };

    // Stub withdrawal queue hash: zero when the batch finalizes no
    // withdrawals, otherwise a hash chain over the encrypted senders.
    let withdrawal_queue_hash = if last_block.finalize_withdrawal_batch_count.is_some() {
        last_block
            .finalize_withdrawal_batch_encrypted_senders
            .iter()
            .fold(B256::ZERO, |acc, sender| {
                keccak256([acc.as_slice(), sender].concat())
            })
    } else {
        B256::ZERO
    };

    Ok(BatchOutput {
        block_transition: BlockTransition {
            prev_block_hash: witness.public_inputs.prev_block_hash,
            next_block_hash,
        },
        deposit_queue_transition,
        withdrawal_queue_hash,
        last_batch_commitment: LastBatchCommitment {
            withdrawal_batch_index: witness.public_inputs.expected_withdrawal_batch_index,
        },
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::Address;
    use crate::fixtures::example_witness;

    #[test]
    fn example_witness_proves() {
        let witness = example_witness();
        let output = prove_zone_batch(&witness).unwrap();
        assert_eq!(
            output.block_transition.prev_block_hash,
            witness.public_inputs.prev_block_hash
        );
        assert_eq!(output.last_batch_commitment.withdrawal_batch_index, 7);
        // The example finalizes a withdrawal batch, so the queue hash is set.
        assert_ne!(output.withdrawal_queue_hash, B256::ZERO);
    }

    #[test]
    fn next_block_hash_uses_spec_block_hash_rule() {
        let witness = example_witness();
        let output = prove_zone_batch(&witness).unwrap();
        let last_block = witness.zone_blocks.last().unwrap();
        let expected = ZoneHeader {
            parent_hash: last_block.parent_hash,
            beneficiary: last_block.beneficiary,
            state_root: witness.initial_zone_state.state_root,
            transactions_root: witness.prev_block_header.transactions_root,
            receipts_root: witness.prev_block_header.receipts_root,
            number: last_block.number,
            timestamp: last_block.timestamp,
            protocol_version: last_block.protocol_version,
        }
        .hash();
        assert_eq!(output.block_transition.next_block_hash, expected);
    }

    #[test]
    fn witness_round_trips_through_json() {
        let witness = example_witness();
        let json = serde_json::to_string(&witness).unwrap();
        let decoded: BatchWitness = serde_json::from_str(&json).unwrap();
        let original = prove_zone_batch(&witness).unwrap();
        let round_tripped = prove_zone_batch(&decoded).unwrap();
        assert_eq!(original, round_tripped);
    }

    #[test]
    fn empty_batch_is_rejected() {
        let mut witness = example_witness();
        witness.zone_blocks.clear();
        assert!(matches!(
            prove_zone_batch(&witness),
            Err(ZoneProverError::EmptyBatch)
        ));
    }

    #[test]
    fn beneficiary_mismatch_is_rejected() {
        let mut witness = example_witness();
        witness.zone_blocks[0].beneficiary = Address::repeat_byte(0xff);
        assert!(matches!(
            prove_zone_batch(&witness),
            Err(ZoneProverError::BeneficiaryMismatch { number: 42 })
        ));
    }

    #[test]
    fn non_consecutive_blocks_are_rejected() {
        let mut witness = example_witness();
        witness.zone_blocks[0].number = 50;
        assert!(matches!(
            prove_zone_batch(&witness),
            Err(ZoneProverError::NonConsecutiveBlocks {
                expected: 42,
                got: 50
            })
        ));
    }

    #[test]
    fn parent_hash_mismatch_is_rejected() {
        let mut witness = example_witness();
        witness.zone_blocks[0].parent_hash = B256::repeat_byte(0xaa);
        assert!(matches!(
            prove_zone_batch(&witness),
            Err(ZoneProverError::ParentHashMismatch)
        ));
    }
}
