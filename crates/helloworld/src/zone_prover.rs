//! Stub of the zone prover.
//!
//! This will eventually decrypt the batch witness and run `prove_zone_batch`
//! to produce a real `BatchOutput`. For now it returns a placeholder batch
//! output derived from the witness so callers can exercise the full
//! prove-and-sign flow end to end.

const STUB_BATCH_OUTPUT_PREFIX: &[u8] = b"stub-batch-output:";

/// Run the (stubbed) zone prover over the given witness and return the
/// serialized batch output.
pub(crate) fn prove_zone_batch(witness: &[u8]) -> Vec<u8> {
    [STUB_BATCH_OUTPUT_PREFIX, witness].concat()
}
