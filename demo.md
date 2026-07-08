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

## 3. Clone this repo and install the verification CLI

Install `tvc_zones_cli` globally so it can be run from anywhere:

```sh
git clone https://github.com/tkhq/tvc-zones-prover-poc.git
cd tvc-zones-prover-poc
cargo install --path crates/tvc_zones_cli
```

## 4. Create the app and deployment

### 4a. App create

`tvc app create` requires a config file, but no hand-editing is needed:
`tvc app init` pre-fills the quorum public key and operator key from your
local CLI state, leaving only the name placeholders. Patch those with `jq`
and pipe the result straight into `app create` via process substitution —
no persistent config file:

```sh
tvc app init --non-interactive --output /tmp/app-template.json
tvc app create --non-interactive --config-file <(
  jq '.name="zones-prover-demo" | .manifestSetParams.name="zones-prover-demo-manifest-set"' \
    /tmp/app-template.json
)
rm /tmp/app-template.json
```

Record from the output:

- **App ID** (`TVC_APP_ID`)
- **Manifest Set Operator IDs** (needed for `tvc deploy approve`)

### 4b. Deployment create — pure CLI args, no config file

`tvc deploy create` supports flag-only operation. Use the **latest
successful `stagex` workflow run on `main`**: every run's "Build
zones_prover image" job prints a **TVC Deployment Details** block (also in
the run's step summary) with the container image URL and expected pivot
digest. Fetch them like so:

```sh
gh run list -R tkhq/tvc-zones-prover-poc -w stagex -b main --json databaseId,conclusion
gh run view <id> -R tkhq/tvc-zones-prover-poc --log | grep -A3 'TVC Deployment Details'
```

Example values from the latest successful main run at the time of writing
(workflow run
[`28911538632`](https://github.com/tkhq/tvc-zones-prover-poc/actions/runs/28911538632),
commit `3b4541f`):

```sh
export TVC_PIVOT_IMAGE_URL='ghcr.io/tkhq/zones_prover:main@sha256:15fb6c54ed1bc0acaab81f62eae7009906129c7acbb45b4facf68349b53d8586'
export TVC_EXPECTED_PIVOT_DIGEST='17f55247f42b177d847c84cd08aa54b770171b637d6d9035bc31ace1c76fafa4'
```

Create the deployment (ports: the server listens on 3000 by default, and
`/health` is served on the same listener):

```sh
tvc deploy create \
  --app-id "$TVC_APP_ID" \
  --qos-version 0.12.0 \
  --pivot-image-url "$TVC_PIVOT_IMAGE_URL" \
  --pivot-path /tvc_app \
  --expected-pivot-digest "$TVC_EXPECTED_PIVOT_DIGEST" \
  --pivot-args='--host,0.0.0.0,--port,3000' \
  --health-check-port 3000 \
  --public-ingress-port 3000 \
  --non-interactive
```

Record the **Deployment ID**, then approve the deployment manifest as an
operator. Interactively the CLI walks you through reviewing the manifest;
non-interactively (CI/agents) you must explicitly acknowledge skipping that
review with `--dangerous-skip-interactive`:

```sh
tvc deploy approve \
  --deploy-id <DEPLOYMENT_UUID> \
  --operator-id <OPERATOR_UUID> \
  --non-interactive --dangerous-skip-interactive
# operator ID comes from the app create output
```

## 5. Wait for the app to be ready

```sh
# Deployment status (manifest approval / provisioning progress):
tvc deploy status --deploy-id <DEPLOYMENT_UUID>

# Live runtime status from the cluster (healthy/desired replica counts):
tvc app status --app-id "$TVC_APP_ID"
```

Repeat until `tvc app status` reports all replicas healthy (e.g.
`Healthy / Desired Replicas: 3/3`). The app's public URL is shown as
`Public Domain` in `tvc app list` (on dev it follows the pattern
`app-<APP_ID>.tvc.dev.turnkey.engineering`).

## 6. Verify end to end with tvc_zones_cli

Run the two-phase verification against the live deployment (the CLI was
installed globally in step 3):

```sh
tvc_zones_cli --url https://<your-app-public-url>
```

Phase 1 (**sequencer**) fetches `/enclave_identity`, verifies the identity
attestation document against the AWS Nitro root, extracts the quorum key
from the attested manifest, encrypts a fake `BatchWitness` to it, submits
it to `/prove_zone_batch`, and verifies the response signatures: the quorum
key against the attested manifest and the ephemeral key via the response's
own attestation document.

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
