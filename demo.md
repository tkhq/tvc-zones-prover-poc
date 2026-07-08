# TVC Zones Prover — End-to-End Demo

## 1. Create a Turnkey organization

**[human]** Follow the Turnkey onboarding at
<https://docs.turnkey.com/getting-started/quickstart>:

1. Sign up at <https://app.turnkey.com> and create an **organization**.
2. Note your **Organization ID** (a UUID, shown in the dashboard under
   *Settings*).
3. Create an **API key pair** (dashboard → *API keys* → *Create API key*, or
   let `tvc login` generate one for you in step 2 and register its public
   key in the dashboard).

Credentials to collect before continuing:

| Credential | Where it comes from |
|---|---|
| `TVC_ORG_ID` | Turnkey organization UUID |
| `TVC_API_KEY_PUBLIC` | hex-encoded compressed P256 public key of your API key |
| `TVC_API_KEY_PRIVATE` | hex-encoded P256 private key of your API key |

## 2. Install the TVC CLI

The `tvc` CLI lives in [tkhq/rust-sdk](https://github.com/tkhq/rust-sdk)
(`tvc/` crate) and is published to crates.io:

```sh
cargo install tvc
```

Authenticate. Either interactively (writes `~/.config/turnkey/`):

```sh
tvc login
```

or fully non-interactively via environment variables (recommended for
agents/CI — all three must be set):

```sh
export TVC_ORG_ID=<your org UUID>
export TVC_API_KEY_PUBLIC=<hex compressed P256 public key>
export TVC_API_KEY_PRIVATE=<hex P256 private key>
export TVC_NON_INTERACTIVE=true   # fail fast instead of prompting
```

## 3. Clone this repo and build the verification CLI

```sh
git clone https://github.com/tkhq/tvc-zones-prover-poc.git
cd tvc-zones-prover-poc
cargo build --bin tvc_zones_cli
```

## 4. Create the app and deployment

### 4a. App create

Generate a quorum key setup and app config, then create the app.
`tvc app create` requires a config file; generate the template with
`tvc app init` and fill it (interactively, or by editing the JSON):

```sh
# Generate + shamir-split a quorum key (see `tvc keys generate-quorum-key --help`),
# or start from the app template and fill in an existing quorum public key:
tvc app init --name zones-prover-demo --output zones-prover-app.json
# edit zones-prover-app.json: quorumPublicKey, manifest/share set operators, ...

tvc app create --config-file zones-prover-app.json
```

Record from the output:

- **App ID** (`TVC_APP_ID`)
- **Manifest Set Operator IDs** (needed for `tvc deploy approve`)

### 4b. Deployment create — pure CLI args, no config file

`tvc deploy create` supports flag-only operation. The container image URL and
expected pivot digest come from this repo's **stagex CI** ("Build
zones_prover image" job): every run of the `stagex` workflow on
[PR #1](https://github.com/tkhq/tvc-zones-prover-poc/pull/1) prints a
**TVC Deployment Details** block (also in the run's step summary) with the
exact values.

Known-good values from the latest successful stagex run at the time of
writing (workflow run
[`28908023492`](https://github.com/tkhq/tvc-zones-prover-poc/actions/runs/28908023492),
commit `7250621`):

```sh
export TVC_PIVOT_IMAGE_URL='ghcr.io/tkhq/zones_prover:pr-1@sha256:71251137bc36c1570280d478bdfd0634b4e91d094f0e13260d8bb2205a91dae5'
export TVC_EXPECTED_PIVOT_DIGEST='e0246e3943de810e7297e530af6a039eccb387e9359731f374321556760c56f7'
```

> To refresh these for a newer commit: open the PR's latest successful
> `stagex` workflow run on GitHub Actions and copy the values from the
> **TVC Deployment Details** step summary, or via the API:
> `gh run list -R tkhq/tvc-zones-prover-poc -w stagex -b <branch> --json databaseId,conclusion`
> then `gh run view <id> -R tkhq/tvc-zones-prover-poc --log | grep -A3 'TVC Deployment Details'`.

Create the deployment (ports: the server listens on 3000 by default, and
`/health` is served on the same listener):

```sh
tvc deploy create \
  --app-id "$TVC_APP_ID" \
  --qos-version v0.12.0 \
  --pivot-image-url "$TVC_PIVOT_IMAGE_URL" \
  --pivot-path /tvc_app \
  --expected-pivot-digest "$TVC_EXPECTED_PIVOT_DIGEST" \
  --pivot-args '--host,0.0.0.0,--port,3000' \
  --health-check-port 3000 \
  --public-ingress-port 3000 \
  --non-interactive
```

Record the **Deployment ID**, then approve the deployment manifest as an
operator:

```sh
tvc deploy approve \
  --deploy-id <DEPLOYMENT_UUID> \
  --operator-id <OPERATOR_UUID>   # from the app create output
```

## 5. Wait for the app to be ready

```sh
# Deployment status (manifest approval / provisioning progress):
tvc deploy status --deploy-id <DEPLOYMENT_UUID>

# Live runtime status from the cluster (ready / health):
tvc app status --app-id "$TVC_APP_ID"
```

Repeat until the app reports ready and note the app's public URL.

## 6. Verify end to end with tvc_zones_cli

Run the two-phase verification against the live deployment:

```sh
./target/debug/tvc_zones_cli --url https://<your-app-public-url>
```

Phase 1 (**sequencer**) fetches `/enclave_identity`, verifies the identity
attestation document against the AWS Nitro root, extracts the ephemeral key
from the attestation document, encrypts a fake `BatchWitness` to it, submits
it to `/prove_zone_batch`, and checks the response signatures against the
attested identity.

Phase 2 (**on-chain verifier**) then verifies the prove response the way a
verifier contract / precompile would: attestation doc decode,
`user_data == sha256(batch_output)`, certificate chain, PCR0-3, the PCR17
manifest commitment, manifest decode + cross-checks, and the pivot hash —
which should equal the **Expected Executable Digest** from step 4b's CI
output for a correctly deployed app.

Expected final output: `all checks passed`.

### Local dry run (no Turnkey account needed)

The same two-phase flow runs against a local mock server (root verification
skipped, everything else identical):

```sh
# terminal 1
make run

# terminal 2
cargo run --bin tvc_zones_cli -- --url http://127.0.0.1:3000 --unsafe-skip-root-verification
```
