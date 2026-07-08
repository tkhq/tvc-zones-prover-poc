# TVC Zones Prover PoC

A proof of concept for running `prove_zone_batch` inside a [Turnkey Verifiable Cloud (TVC)](https://docs.turnkey.com) enclave. The request/response types match the prover input definitions from the [tempo zones spec](https://github.com/tempoxyz/zones) (`BatchWitness` in, `BatchOutput` commitments out), but the proof itself is still a stub: `/prove_zone_batch` validates structural invariants of the submitted witness, derives placeholder commitments, and returns the batch output as structured JSON signed by the quorum and ephemeral keys (the signatures are over its canonical QOS JSON (`qos_json`) encoding, which verifiers recompute by re-serializing the decoded `BatchOutput`), plus the NSM attestation doc (with the sha256 of the canonical batch output bytes in `user_data` — the NSM caps `user_data` at 512 bytes, so the doc commits to the hash) and the QOS manifest as structured JSON.

Based on [tkhq/tvc-template](https://github.com/tkhq/tvc-template).

For a full zero-to-deployed walkthrough (Turnkey org setup, TVC CLI app
creation and deployment, end-to-end verification), see **[demo.md](demo.md)**.

## Repository layout

```
crates/
├── zones_prover/     # TVC app server: /health, /enclave_identity, /prove_zone_batch, /metrics
├── tempo_zone_stubs/      # all functions/types we expect to import directly from tempoxyz/zones (spec-mirrored batch types + stub prover are staged here until tempo publishes them)
├── tvc_zones_cli/    # verification CLI: sequencer + onchain-verifier emulation
├── tvc_utils/        # dev/test utilities, not core app logic: mock NSM + fake manifest generator
└── metrics/          # Prometheus tower layer + /metrics handler
images/               # stagex Containerfile for the reproducible enclave image
Makefile              # build/test/lint/local-keys/run targets
demo.md               # end-to-end deployment walkthrough
```

## Running locally

```sh
make run  # starts the server with --mock-nsm and a locally generated manifest and keys
```

## Verification CLI

`tvc_zones_cli` exercises a running TVC app in two clearly labeled phases,
emulating the two parties that interact with the enclave.

### Phase 1: sequencer

What a sequencer does to submit a zone batch:

1. `GET /enclave_identity` (manifest, quorum key, ephemeral key, fresh
   attestation doc).
2. **Verify the identity attestation doc**: certificate chain to the AWS
   Nitro root, `user_data` == canonical QOS JSON manifest hash (the QOS
   convention), and the PCR17 live manifest commitment.
3. **Extract the ephemeral key FROM the attestation doc** (never from the
   unauthenticated JSON field).
4. **Encrypt the `BatchWitness`** to the attested ephemeral key (qos_p256).
5. `POST /prove_zone_batch` with the encrypted witness.
6. **Verify the response**: the structured `batch_output` matches the
   locally computed `BatchOutput`, the signing keys match the attested
   identity, and both signatures verify over the signing payload — the
   canonical QOS JSON (`qos_json`) encoding of the `BatchOutput`,
   re-serialized locally (the enclave signs exactly those bytes).

### Phase 2: on-chain verifier

What an on-chain verifier contract / precompile does with the prove
response, step by step:

0. **Recompute the canonical signed bytes**: re-serialize the response's
   structured `batch_output` as canonical QOS JSON (`qos_json::to_vec`)
   and verify the quorum and ephemeral signatures over exactly those
   recomputed bytes, never over unparsed response bytes.
1. **Decode** the attestation document (COSE Sign1 → `AttestationDoc`) and
   check `user_data == sha256(batch_output)` and that the doc's
   `public_key` is the ephemeral key that signed the batch output.
2. **Verify the certificate chain** against the pinned AWS Nitro root
   certificate and the COSE Sign1 signature
   (`qos_nsm::nitro::attestation_doc_from_der`).
3. **Print PCR0/1/2/3** (enclave image, kernel, application, IAM role) for
   comparison against known-good release values.
4. **Verify the QOS live manifest commitment**: the canonical QOS JSON hash
   of the manifest plus the attested ephemeral key must extend to the value
   in PCR17 (`LIVE_MANIFEST_COMMITMENT_PCR_INDEX` in qos 0.12; PCR16 is the
   setup/boot commitment).
5. **Decode the manifest** (JSON → `ManifestEnvelopeV2`) and print its key
   fields, cross-checking that the manifest's quorum key matches the key
   that signed the batch output and that the doc's PCR0-3 match the
   manifest's expected enclave PCRs.
6. **Print the manifest pivot (app) hash** for comparison against a
   known-good reproducible build of the app binary.

For simplicity there are no baked-in expected values: the CLI prints the
measured values and states what to compare them against.

### Against live infrastructure (default posture)

```sh
cargo run --bin tvc_zones_cli -- --url https://your-deployed-tvc-app
```

All steps run, including full certificate chain verification against
the AWS Nitro root. Expected output ends with `all checks passed` and the
binary exits 0; any failed check prints `FAILED: ...` and exits 1.

### Against a local mock server

Mock attestation documents cannot chain to the AWS root, so step 2 must be
explicitly skipped (everything else still runs, including the PCR17
manifest-commitment verification — the mock NSM commits to the local fake
manifest exactly like a real enclave would):

```sh
# terminal 1: run the server locally (mock NSM + generated fake manifest)
make run

# terminal 2: run the verification, skipping only root verification
cargo run --bin tvc_zones_cli -- --url http://127.0.0.1:3000 --unsafe-skip-root-verification
```

`--unsafe-skip-root-verification` prints a loud warning and means the
attestation document is not authenticated — never use it against
production infrastructure.

## Endpoints

```sh
$ curl localhost:3000/health
{"status":"healthy"}

$ curl localhost:3000/enclave_identity
{"manifest":{...},"quorum_public_key":"...","ephemeral_public_key":"...","attestation_doc":"..."}
# manifest is the v2 manifest envelope as structured JSON (readable directly;
# verifiers recompute its canonical QOS JSON hash locally); attestation_doc is
# a fresh COSE Sign1 doc with the canonical QOS JSON manifest hash in user_data
# and the ephemeral public key in public_key. Callers verify the doc and then
# encrypt request payloads to the attested ephemeral key.

$ curl -X POST \
  -H 'content-type: application/json' \
  -d '{"encrypted_witness":"<hex qos_p256 envelope over the JSON serialized BatchWitness>"}' \
  localhost:3000/prove_zone_batch
{"batch_output":{...},"quorum_key_signature":"...","quorum_public_key":"...","ephemeral_key_signature":"...","ephemeral_public_key":"...","attestation_doc":"...","manifest":{...}}
# batch_output is the BatchOutput commitments as structured JSON; both
# signatures are over its canonical QOS JSON (qos_json) encoding, which
# verifiers recompute by re-serializing the decoded BatchOutput. See
# crates/tempo_zone_stubs/src/lib.rs for the full BatchWitness definition.
# The witness must be encrypted to the ephemeral key from /enclave_identity.

$ curl localhost:3000/metrics
# Prometheus metrics
```
