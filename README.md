# TVC Zones Prover PoC

A proof of concept for running `prove_zone_batch` inside a [Turnkey Verifiable Cloud (TVC)](https://docs.turnkey.com) enclave. The prover is currently a stub: the endpoint runs a placeholder prover over the submitted witness and returns the batch output signed by the quorum and ephemeral keys, plus stub attestation doc and manifest values.

## Endpoints

```sh
$ curl localhost:44020/health
{"status":"healthy"}

$ curl -X POST \
  -H 'content-type: application/json' \
  -d '{"witness":"deadbeef"}' \
  localhost:44020/prove_zone_batch
{"batch_output":"...","quorum_key_signature":"...","quorum_public_key":"...","ephemeral_key_signature":"...","ephemeral_public_key":"...","attestation_doc":"...","manifest":"..."}

$ curl localhost:44020/metrics
# Prometheus metrics
```
