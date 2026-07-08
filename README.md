# TVC Zones Prover PoC

A proof of concept for running `prove_zone_batch` inside a [Turnkey Verifiable Cloud (TVC)](https://docs.turnkey.com/features/verifiable-cloud/overview) enclave. The request/response types match the prover input definitions from the [tempo zones spec](https://github.com/tempoxyz/zones/blob/main/specs/spec.md#witness-structure) (`BatchWitness` in, `BatchOutput` commitments out), but the proof itself is still a stub: `/prove_zone_batch` returns mocked batch output signed by the quorum and ephemeral keys, along with an NSM attestation doc binding the batch output. The [`prove_zone_batch` handler](crates/zones_prover/src/handlers/prove.rs) is the heart of what happens inside the enclave: decrypt the witness with the quorum key, prove, sign the canonical QOS JSON batch output with the quorum and ephemeral keys, and attach a fresh attestation doc.

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

What an on-chain verifier contract / precompile does with the prove
response, step by step:

0. **Recompute the canonical signed bytes**: re-serialize the response's
   structured `batch_output` as canonical QOS JSON and verify the quorum
   and ephemeral signatures over those bytes.
1. **Verify the attestation binding**: decode the attestation document
   and check `user_data == sha256(batch_output)`.
2. **Verify the certificate chain** against the pinned AWS Nitro root
   certificate and the COSE Sign1 signature.
3. **Print PCR0/1/2/3** for comparison against known-good release values.
4. **Verify the QOS live manifest commitment**: the hash of the manifest
   plus the attested key must extend to the value in PCR17.
5. **Decode the manifest** and print its key fields, cross-checking the
   quorum key and the enclave PCRs.
6. **Print the manifest pivot hash** for comparison against a known-good
   reproducible build of the app.

> **Note**: verifying the attestation binding (steps 1–5) makes the
> step 0 signatures unnecessary. Conversely, a signature alone suffices for a
> verifier that trusts a pinned quorum key, or that has verified once
> that a valid attestation doc commits to the ephemeral public key via
> the PCR17 live manifest commitment.

For simplicity there are no baked-in expected values: the CLI prints the
measured values and states what to compare them against.

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
{"batch_output":{...},"quorum_key_signature":"...","quorum_public_key":"...","ephemeral_key_signature":"...","ephemeral_public_key":"...","attestation_doc":"...","manifest":{...}}
# batch_output is the BatchOutput commitments as structured JSON; both
# signatures are over its canonical QOS JSON encoding. See
# crates/tempo_zones_stubs/src/lib.rs for the full BatchWitness definition.

$ curl localhost:3000/metrics
# Prometheus metrics
```
