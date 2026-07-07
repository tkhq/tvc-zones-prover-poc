# TVC Zones Prover PoC

A proof of concept for running `prove_zone_batch` inside a [Turnkey Verifiable Cloud (TVC)](https://docs.turnkey.com) enclave. The prover is currently a stub: each endpoint runs a placeholder prover over the submitted witness and returns the batch output signed by the quorum and ephemeral keys, plus the NSM attestation doc (with the batch output in `user_data`) and the QOS manifest. `/prove_zone_batch` uses the real NSM and manifest, so it only works inside an enclave; `/mock_attestation/prove_zone_batch` returns stub attestation doc and manifest values for use anywhere.

Based on [tkhq/tvc-template](https://github.com/tkhq/tvc-template).

## Endpoints

```sh
$ curl localhost:44020/health
{"status":"healthy"}

$ curl -X POST \
  -H 'content-type: application/json' \
  -d '{"witness":"deadbeef"}' \
  localhost:44020/prove_zone_batch
{"batch_output":"...","quorum_key_signature":"...","quorum_public_key":"...","ephemeral_key_signature":"...","ephemeral_public_key":"...","attestation_doc":"...","manifest":"..."}

$ curl -X POST \
  -H 'content-type: application/json' \
  -d '{"witness":"deadbeef"}' \
  localhost:44020/mock_attestation/prove_zone_batch
# same shape, with stub attestation_doc and manifest values

$ curl localhost:44020/metrics
# Prometheus metrics
```
