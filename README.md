# TVC Zones Prover PoC

A proof of concept for running `prove_zone_batch` inside a [Turnkey Verifiable Cloud (TVC)](https://docs.turnkey.com) enclave. The request/response types match the prover input definitions from the [tempo zones spec](https://github.com/tempoxyz/zones/blob/main/specs/spec.md#witness-structure) (`BatchWitness` in, `BatchOutput` commitments out), but the proof itself is still a stub: `/prove_zone_batch` validates structural invariants of the submitted witness, derives placeholder commitments, and returns the batch output signed by the quorum and ephemeral keys, along with an NSM attestation doc committing to the output and the QOS manifest.

Based on [tkhq/tvc-template](https://github.com/tkhq/tvc-template).

For a full zero-to-deployed walkthrough (Turnkey org setup, TVC CLI app
creation and deployment, end-to-end verification), see **[demo.md](demo.md)**.

## Repository layout

```
crates/
├── zones_prover/      # TVC app server: /health, /enclave_identity, /prove_zone_batch, /metrics
├── tempo_zone_stubs/  # spec-mirrored batch types + stub prover, staged here until tempo publishes them
├── tvc_zones_cli/     # verification CLI: sequencer + onchain-verifier emulation
├── tvc_utils/         # dev/test utilities: mock NSM + fake manifest generator
├── metrics/           # Prometheus tower layer + /metrics handler
└── e2e/               # end-to-end tests against a spawned server
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
   unauthenticated JSON field) and the quorum key FROM the attested
   manifest.
4. **Encrypt the `BatchWitness`** to the attested quorum key (qos_p256).

> **Why the quorum key and not the ephemeral key?** Ephemeral keys are
> per-replica, and `/enclave_identity` only returns whichever replica the
> load balancer hits. In practice this is likely replaced by a TVC endpoint
> listing all live enclaves for an app, so a sequencer can encrypt to every
> relevant ephemeral key. That endpoint is not live yet, so the demo
> encrypts to the quorum key.
5. `POST /prove_zone_batch` with the encrypted witness.
6. **Verify the response**: the structured `batch_output` matches the
   locally computed `BatchOutput`, the quorum key matches the attested
   manifest, the response's own attestation doc authenticates its
   ephemeral key (the proving replica may differ from the one that served
   the identity), and both signatures verify over the canonical QOS JSON
   (`qos_json`) encoding of the `BatchOutput`, re-serialized locally.

### Phase 2: on-chain verifier

What an on-chain verifier contract / precompile does with the prove
response, step by step:

0. **Recompute the canonical signed bytes**: re-serialize the response's
   structured `batch_output` as canonical QOS JSON and verify the quorum
   and ephemeral signatures over those recomputed bytes.
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
   in PCR17.
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
# manifest is the v2 manifest envelope as structured JSON; attestation_doc is
# a fresh COSE Sign1 doc committing to the manifest and the ephemeral key.
# Callers verify the doc, then encrypt request payloads to the quorum key
# from the attested manifest.

$ curl -X POST \
  -H 'content-type: application/json' \
  -d '{"encrypted_witness":"<hex qos_p256 envelope over the JSON serialized BatchWitness>"}' \
  localhost:3000/prove_zone_batch
{"batch_output":{...},"quorum_key_signature":"...","quorum_public_key":"...","ephemeral_key_signature":"...","ephemeral_public_key":"...","attestation_doc":"...","manifest":{...}}
# batch_output is the BatchOutput commitments as structured JSON; both
# signatures are over its canonical QOS JSON encoding. See
# crates/tempo_zone_stubs/src/lib.rs for the full BatchWitness definition.

$ curl localhost:3000/metrics
# Prometheus metrics
```
