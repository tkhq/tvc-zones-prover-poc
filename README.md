# TVC Zones Prover PoC

A proof of concept for running `prove_zone_batch` inside a [Turnkey Verifiable Cloud (TVC)](https://docs.turnkey.com/features/verifiable-cloud/overview) enclave. The request/response types match the prover input definitions from the [tempo zones spec](https://github.com/tempoxyz/zones/blob/main/specs/spec.md#witness-structure) (`BatchWitness` in, `BatchOutput` commitments out), but the proof itself is still a stub: `/prove_zone_batch` returns the mocked batch output as canonical QOS JSON bytes plus three independent proofs over those bytes. The [`prove_zone_batch` handler](crates/zones_prover/src/handlers/prove.rs) is the heart of what happens inside the enclave: decrypt the witness with the quorum key, prove, sign the canonical QOS JSON batch output with the quorum and ephemeral keys, and attach fresh attestation docs.

Based on [tkhq/tvc-template](https://github.com/tkhq/tvc-template).

For a full zero-to-deployed walkthrough (Turnkey org setup, TVC CLI app
creation and deployment, end-to-end verification), see **[demo.md](demo.md)**.

## Repository layout

```
crates/
├── zones_prover/       # TVC app server: /health, /enclave_identity, /prove_zone_batch, /metrics
├── tempo_zones_stubs/  # spec-mirrored batch types + stub prover, staged here until tempo publishes them
├── tvc_zones_cli/      # verification CLI: sequencer + onchain-verifier emulation
├── tvc_utils/          # dev/test utilities: mock NSM + fake manifest generator
├── metrics/            # Prometheus tower layer + /metrics handler
└── e2e/                # end-to-end tests against a spawned server
images/                # stagex Containerfile for the reproducible enclave image
Makefile               # build/test/lint/local-keys/run targets
demo.md                # end-to-end deployment walkthrough
```

## Verification CLI

`tvc_zones_cli` exercises a running TVC app in two clearly labeled phases,
emulating the two parties that interact with the enclave.

### Phase 1: sequencer

What a sequencer does to submit a zone batch:

1. `GET /enclave_identity` (manifest, quorum key, ephemeral key, fresh
   attestation doc).
2. **Verify the identity attestation doc**: certificate chain to the AWS
   Nitro root, `user_data` == manifest hash, and the PCR17 live manifest
   commitment.
3. **Extract the quorum key** from the attested manifest.
4. **Encrypt the `BatchWitness`** to the quorum key.
5. `POST /prove_zone_batch` with the encrypted witness. The response is
   decoded and trusted as-is here; the on-chain verifier phase is
   responsible for verifying it.

> **Why the quorum key and not the ephemeral key?** Ephemeral keys are
> per-replica, and `/enclave_identity` only returns whichever replica the
> load balancer hits. A future TVC endpoint listing all live enclaves for
> an app would let a sequencer encrypt to every relevant ephemeral key.

### Phase 2: on-chain verifier

The prove response carries the batch output as canonical QOS JSON bytes —
the exact bytes every proof binds — plus three independent proofs. Any one
proof suffices; they differ in what the chain has pinned out of band:

1. **QK model** (`qk_proof`): pins the deployment-wide quorum public key.
   One signature verification over the batch output bytes; the cheapest
   on chain.
2. **EK model** (`ek_proof`): pins the manifest hash and PCR0-3. A boot
   proof attestation doc (`user_data == manifest hash`, PCR17 live
   manifest commitment, cert chain to the AWS Nitro root) establishes the
   per-replica ephemeral key, which verifies the batch signature. The boot
   proof only changes when a replica boots, so it can be verified once and
   the key cached.
3. **Attestation-binding model** (`nsm_proof`): pins the manifest hash and
   PCR0-3. A per-request attestation doc binds `sha256(batch_output)` in
   `user_data`, anchored to the pinned manifest hash via the PCR17 live
   commitment.

Both attestation-based models pin PCR0-3 alongside the manifest hash: the
PCR17 commitment is extended by software inside the enclave, so it only
carries authority if PCR0-2 prove that software is a known-good QOS
release.

The manifest itself is not part of the response: an on-chain verifier
already knows the manifest hash / quorum key / PCRs, and the manifest body
is available from `GET /enclave_identity` for debugging.

For simplicity there are no baked-in expected values: the CLI sources the
"pinned" values from the sequencer phase's independently verified enclave
identity.

### Against live infrastructure

```sh
cargo run --bin tvc_zones_cli -- --url https://your-deployed-tvc-app
```

## Endpoints

```sh
$ curl localhost:3000/health
{"status":"healthy"}

$ curl localhost:3000/enclave_identity
{"manifest":{...},"quorum_public_key":"...","ephemeral_public_key":"...","attestation_doc":"..."}
# manifest is the v2 manifest envelope as structured JSON; attestation_doc is
# a fresh COSE Sign1 doc committing to the manifest.
# Callers verify the doc, then encrypt request payloads to the quorum key
# from the attested manifest.

$ curl -X POST \
  -H 'content-type: application/json' \
  -d '{"encrypted_witness":"<hex-encoded encrypted JSON serialized BatchWitness>"}' \
  localhost:3000/prove_zone_batch
{"batch_output":"...","qk_proof":{"qk_sig":"..."},"ek_proof":{"bootproof_att_doc":"...","ek_sig":"..."},"nsm_proof":{"att_doc":"..."}}
# batch_output is the canonical QOS JSON encoding of the BatchOutput
# commitments, hex-encoded; every proof binds exactly those bytes. See
# crates/tempo_zones_stubs/src/lib.rs for the full BatchWitness definition.

$ curl localhost:3000/metrics
# Prometheus metrics
```
