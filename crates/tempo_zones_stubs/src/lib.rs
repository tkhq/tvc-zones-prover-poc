//! All functions and types we expect to import directly from the tempo
//! repo (<https://github.com/tempoxyz/zones>) — a staging ground.
//!
//! What tempo already publishes is re-exported: [`ZoneHeader`] plus the
//! [`zone_primitives`] and [`alloy_primitives`] crates. The batch types
//! ([`BatchWitness`], [`BatchOutput`], ...) and the stub
//! [`prover::prove_zone_batch`] exist only in tempo's spec (`specs/spec.md`,
//! "Proving System"), so they are mirrored here and get deleted once tempo
//! publishes them as Rust code.
//!
//! The exception is [`fixtures`] (behind the `fixtures` feature): PoC-local
//! fake data, never expected from tempo.

pub mod prover;

// Available to this crate's own tests unconditionally; external users opt
// in via the `fixtures` feature.
#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;

pub use alloy_primitives;
pub use alloy_primitives::{Address, B256, Bytes, U256};
pub use zone_primitives;
pub use zone_primitives::ZoneHeader;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Public inputs committed by the proof system. The portal passes these to
/// the verifier and the proof must be consistent with them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs {
    /// Previous batch's block hash (must equal `portal.blockHash`).
    pub prev_block_hash: B256,
    /// Tempo block number for the batch (must equal portal's
    /// `tempoBlockNumber`).
    pub tempo_block_number: u64,
    /// Anchor Tempo block number (`tempo_block_number` or a recent block in
    /// the EIP-2935 window).
    pub anchor_block_number: u64,
    /// Anchor Tempo block hash (must equal portal's EIP-2935 lookup).
    pub anchor_block_hash: B256,
    /// Expected withdrawal batch index (passed by the portal as
    /// `withdrawalBatchIndex + 1`).
    pub expected_withdrawal_batch_index: u64,
    /// Registered sequencer (passed by the portal; zone block beneficiary
    /// must match).
    pub sequencer: Address,
}

/// Complete witness of zone blocks and their dependencies. Top-level input
/// to the zone prover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchWitness {
    /// Public inputs committed by the proof system.
    pub public_inputs: PublicInputs,
    /// Previous batch's block header (for state-root binding).
    pub prev_block_header: ZoneHeader,
    /// Zone blocks to execute.
    pub zone_blocks: Vec<ZoneBlock>,
    /// Initial zone state.
    pub initial_zone_state: ZoneStateWitness,
    /// Tempo state proofs for Tempo reads.
    pub tempo_state_proofs: BatchStateProof,
    /// Tempo headers for ancestry verification (only in ancestry mode).
    /// Ordered from `tempo_block_number + 1` to `anchor_block_number`.
    pub tempo_ancestry_headers: Vec<Bytes>,
}

/// A zone block to execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneBlock {
    /// Block number.
    pub number: u64,
    /// Parent block hash.
    pub parent_hash: B256,
    /// Timestamp.
    pub timestamp: u64,
    /// Beneficiary (must match the registered sequencer).
    pub beneficiary: Address,
    /// Protocol version encoded into the zone block header.
    pub protocol_version: u64,
    /// Tempo header RLP used by the call (`ZoneInbox.advanceTempo`). If
    /// `None`, the block does not advance Tempo and the binding carries over.
    #[serde(default)]
    pub tempo_header_rlp: Option<Bytes>,
    /// Deposits processed by the system tx (oldest first, unified queue).
    /// Must be empty if `tempo_header_rlp` is `None`.
    pub deposits: Vec<QueuedDeposit>,
    /// Decryption data for encrypted deposits in the system tx. Must be
    /// empty if `tempo_header_rlp` is `None`.
    pub decryptions: Vec<DecryptionData>,
    /// Tokens enabled by the system tx, in the exact calldata order passed
    /// to `ZoneInbox.advanceTempo`. Must be empty if `tempo_header_rlp` is
    /// `None`.
    pub enabled_tokens: Vec<EnabledToken>,
    /// Sequencer-only: finalize a batch (only in the final block, must be
    /// last). Uses `U256` to match Solidity
    /// `finalizeWithdrawalBatch(uint256 count)`.
    pub finalize_withdrawal_batch_count: Option<U256>,
    /// Exact calldata array passed to
    /// `ZoneOutbox.finalizeWithdrawalBatch(count, blockNumber, encryptedSenders)`.
    /// Required iff `finalize_withdrawal_batch_count` is present.
    pub finalize_withdrawal_batch_encrypted_senders: Vec<Bytes>,
    /// Transactions to execute (opaque encoded transactions for the stub).
    pub transactions: Vec<Bytes>,
}

/// Mirrors the Solidity `QueuedDeposit` struct from `IZone.sol`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedDeposit {
    /// Regular or encrypted deposit.
    pub deposit_type: DepositType,
    /// `abi.encode(Deposit)` or `abi.encode(EncryptedDeposit)`.
    pub deposit_data: Bytes,
    /// Whether the deposit was rejected.
    pub rejected: bool,
}

/// Deposit variant tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DepositType {
    /// Plaintext deposit.
    Regular,
    /// Encrypted deposit.
    Encrypted,
}

/// Mirrors the Solidity `EnabledToken` struct from `IZone.sol`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnabledToken {
    /// Token contract address.
    pub token: Address,
    /// Token name.
    pub name: String,
    /// Token symbol.
    pub symbol: String,
    /// Token currency.
    pub currency: String,
}

/// Mirrors the Solidity `DecryptionData` struct from `IZone.sol`. Provided
/// by the sequencer for each encrypted deposit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionData {
    /// ECDH shared secret (x-coordinate).
    pub shared_secret: B256,
    /// Y coordinate parity of the shared secret point.
    pub shared_secret_y_parity: u8,
    /// Chaum-Pedersen proof of correct decryption.
    pub cp_proof: ChaumPedersenProof,
}

/// Chaum-Pedersen discrete-log equality proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaumPedersenProof {
    /// Response: `s = r + c * privSeq (mod n)`.
    pub s: B256,
    /// Challenge: `c = hash(G, ephemeralPub, pubSeq, sharedSecretPoint, R1, R2)`.
    pub c: B256,
}

/// Initial zone state witness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneStateWitness {
    /// Zone state root at start of batch.
    pub state_root: B256,
    /// Deduplicated pool of all zone-state MPT nodes, keyed by
    /// `keccak256(rlp(node))`.
    pub node_pool: HashMap<B256, Bytes>,
    /// Decoded account leaves needed to bootstrap execution.
    pub account_reads: Vec<ZoneAccountRead>,
    /// Decoded storage leaves needed to bootstrap execution.
    pub storage_reads: Vec<ZoneStorageRead>,
}

/// Decoded account leaf proven against the initial zone state root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneAccountRead {
    /// Account address.
    pub account: Address,
    /// Account nonce.
    pub nonce: u64,
    /// Account balance.
    pub balance: U256,
    /// Account code hash.
    pub code_hash: B256,
    /// Optional code preimage; must satisfy `keccak256(code) == code_hash`.
    #[serde(default)]
    pub code: Option<Bytes>,
}

/// Decoded storage leaf proven against the initial zone state root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneStorageRead {
    /// Account address.
    pub account: Address,
    /// Storage slot.
    pub slot: U256,
    /// Storage value.
    pub value: U256,
}

/// Tempo state proofs for Tempo reads performed during the batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchStateProof {
    /// Deduplicated pool of all MPT nodes, keyed by `keccak256(rlp(node))`.
    pub node_pool: HashMap<B256, Bytes>,
    /// Tempo state reads verified against the shared node pool.
    pub reads: Vec<L1StateRead>,
}

/// A single Tempo (L1) state read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L1StateRead {
    /// Which zone block performed this read.
    pub zone_block_index: u64,
    /// Which Tempo block to read from.
    pub tempo_block_number: u64,
    /// Tempo account address.
    pub account: Address,
    /// Storage slot.
    pub slot: U256,
    /// Expected value.
    pub value: U256,
}

/// Zone block hash transition covering all blocks in the batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockTransition {
    /// Block hash before the batch.
    pub prev_block_hash: B256,
    /// Block hash after the batch.
    pub next_block_hash: B256,
}

/// Deposit queue progress across the batch.
///
/// `u64` fields use the QOS string-or-numeric JSON encoding so the type
/// round-trips through canonical QOS JSON, the signed encoding of
/// [`BatchOutput`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositQueueTransition {
    /// Deposit queue processed hash before the batch.
    pub prev_processed_hash: B256,
    /// Deposit queue processed hash after the batch.
    pub next_processed_hash: B256,
    /// Deposit counter before the batch.
    #[serde(with = "qos_json::string_or_numeric")]
    pub prev_deposit_number: u64,
    /// Deposit counter after the batch.
    #[serde(with = "qos_json::string_or_numeric")]
    pub next_deposit_number: u64,
}

/// `withdrawal_batch_index` read from `ZoneOutbox.lastBatch`.
///
/// `u64` encoding: see [`DepositQueueTransition`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastBatchCommitment {
    /// Withdrawal batch index after the batch.
    #[serde(with = "qos_json::string_or_numeric")]
    pub withdrawal_batch_index: u64,
}

/// Commitments produced by the state transition function for onchain
/// verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchOutput {
    /// `prev_block_hash` to `next_block_hash` covering all blocks in the
    /// batch.
    pub block_transition: BlockTransition,
    /// Deposit queue progress across the batch.
    pub deposit_queue_transition: DepositQueueTransition,
    /// Hash chain of withdrawals finalized in this batch (zero if none).
    pub withdrawal_queue_hash: B256,
    /// `withdrawal_batch_index` read from `ZoneOutbox.lastBatch`.
    pub last_batch_commitment: LastBatchCommitment,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn batch_output_round_trips_through_canonical_qos_json() {
        let output = BatchOutput {
            block_transition: BlockTransition {
                prev_block_hash: B256::repeat_byte(0x11),
                next_block_hash: B256::repeat_byte(0x22),
            },
            deposit_queue_transition: DepositQueueTransition {
                prev_processed_hash: B256::repeat_byte(0x33),
                next_processed_hash: B256::repeat_byte(0x44),
                prev_deposit_number: 100,
                next_deposit_number: 101,
            },
            withdrawal_queue_hash: B256::repeat_byte(0x55),
            last_batch_commitment: LastBatchCommitment {
                withdrawal_batch_index: 7,
            },
        };
        // Plain serde JSON round trip.
        let json = serde_json::to_string(&output).unwrap();
        let decoded: BatchOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, output);
        // Canonical QOS JSON (the signed encoding) round trip: decode and
        // re-encode must reproduce the exact canonical bytes.
        let canonical = qos_json::to_vec(&output).unwrap();
        let decoded: BatchOutput = serde_json::from_slice(&canonical).unwrap();
        assert_eq!(decoded, output);
        assert_eq!(qos_json::to_vec(&decoded).unwrap(), canonical);
    }
}
