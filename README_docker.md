# Running the CSR Attestation Example with Docker and a TPM Simulator

This document explains how to run the [`csr-attestation-tpm-example`](README.md)
entirely inside Docker using a software TPM 2.0 simulator instead of bare-metal
TPM hardware. No physical TPM is required.

---

## Why a Simulator?

The main README explicitly warns:

> **DON'T RUN THIS ON BARE METAL!** Running this code on your bare-metal TPM
> risks losing TPM assets (keys, certificates) or causing your OS to fail to boot.

A software TPM simulator is the safe, reproducible alternative. It behaves
identically to a real TPM from the perspective of `tpm2-tools`, but is just a
process that you can start, stop, and reset freely.

---

## Which Simulator Is Used?

The simulator is the **TCG reference TPM 2.0 implementation** maintained by the
Trusted Computing Group at
[github.com/TrustedComputingGroup/TPM](https://github.com/TrustedComputingGroup/TPM).
This is the same simulator used internally by the
[tpm-rs project](https://github.com/tpm-rs/tpm-rs) for its own integration tests
(see `client/Dockerfile` in that repo). It exposes the standard **Microsoft TPM
Simulator (mssim) protocol** over TCP, which `tpm2-tools` natively understands
through its pluggable TCTI (TPM Command Transmission Interface) layer.

---

## Files Added to This Repository

```
docker/
├── Dockerfile.simulator   # Builds the TCG reference C simulator from source
├── Dockerfile.client      # Builds tpm2-tss, tpm2-tools (≥5.7), OpenSSL,
│                          # and the Python environment, then copies the scripts
├── docker-compose.yml     # Wires the two containers together
└── run.sh                 # Convenience wrapper – build, start, run, teardown
```

---

## Architecture

```
┌─────────────────────── Docker Compose Network ─────────────────────────────┐
│                                                                              │
│  ┌────────────────────────────────────────┐                                  │
│  │         simulator container            │                                  │
│  │                                        │                                  │
│  │  TCG Reference TPM 2.0 Simulator       │                                  │
│  │  (built from TrustedComputingGroup/TPM)│                                  │
│  │                                        │                                  │
│  │  TCP :2321  ◄──── TPM commands ────────┼──────────────┐                   │
│  │  TCP :2322  ◄──── Platform control ────┼──────────────┤                   │
│  └────────────────────────────────────────┘              │                   │
│                                                           │                   │
│  ┌────────────────────────────────────────────────────┐  │                   │
│  │              client container                      │  │                   │
│  │                                                    │  │                   │
│  │  tpm2-tss  (TCTI / mssim transport layer)  ────────┼──┘                   │
│  │      │                                             │                      │
│  │  tpm2-tools  (tpm2_createek, tpm2_certify, …)      │                      │
│  │      │                                             │                      │
│  │  OpenSSL  (CA creation, CSR signing, verification) │                      │
│  │      │                                             │                      │
│  │  Python venv  (create_cri_from_tcg_attest_certify, │                      │
│  │                attach_sig_to_cri)                  │                      │
│  │                                                    │                      │
│  │  Scripts: 1_makeCA → 2_initial_provision →         │                      │
│  │           3_createkey → 4_createcsr → 5_verifykey  │                      │
│  └────────────────────────────────────────────────────┘                      │
│                                  │                                           │
└──────────────────────────────────┼───────────────────────────────────────────┘
                                   │ volume mount (..:/app)
                          ┌────────┴──────────┐
                          │   Host filesystem  │
                          │                   │
                          │  ca/              │  ← CA key & certificate
                          │  client/          │  ← keys, attestation, CSR
                          │  verifier/        │  ← verification inputs/outputs
                          └───────────────────┘
```

### How `tpm2-tools` Talks to the Simulator

Every `tpm2_*` command goes through the **tpm2-tss** library, which provides a
pluggable transport layer called the **TCTI** (TPM Command Transmission
Interface). The environment variable:

```bash
TPM2TOOLS_TCTI="mssim:host=simulator,port=2321"
```

selects the `mssim` TCTI driver. When the first command runs:

1. **tpm2-tss** opens a TCP connection to `simulator:2321` (the command port).
2. It simultaneously sends `PowerOn` and `NV_ON` platform control messages to
   `simulator:2322` (the platform port). These signals simulate the hardware
   power-on sequence.
3. The caller then issues `tpm2_startup -c` (Clear), which runs the TPM
   `TPM2_Startup` command. This initialises the TPM's internal state, equivalent
   to what the firmware does on a real machine during POST.
4. All subsequent `tpm2_*` calls reuse the same TCP connection.

Inside Docker Compose, the hostname `simulator` resolves automatically to the
simulator container's internal IP address via the default Compose network.

### Why No `tpm2-abrmd`?

On bare metal, `tpm2-abrmd` (the Access Broker / Resource Manager daemon) is
recommended because the physical TPM has a very limited number of key slots.
`tpm2-abrmd` manages key eviction on behalf of applications.

With the software simulator, key slots are not a hardware constraint, and every
container run starts with a clean TPM state. There is no need for `tpm2-abrmd`,
so the client container connects **directly** to the simulator via TCP without
a resource manager in between.

---

## Prerequisites

| Requirement | Version |
|-------------|---------|
| Docker Engine | 24.x or later |
| Docker Compose plugin | v2 (`docker compose`, not `docker-compose`) |

A Docker Compose v1 fallback (`docker-compose`) is handled automatically by
`run.sh` if the v2 plugin is not present.

---

## Quick Start

```bash
# From the repository root:
./docker/run.sh
```

That single command will:

1. Build both container images (this takes several minutes on first run because
   tpm2-tss and tpm2-tools are compiled from source).
2. Start the simulator container in the background.
3. Wait until the simulator is healthy (listening on port 2321).
4. Issue `tpm2_startup -c` to initialise the TPM state.
5. Run all five scripts in order inside the client container.
6. Stop and remove the containers when finished.

Output artefacts are written directly to your local `ca/`, `client/`, and
`verifier/` directories via the volume mount.

---

## Step-by-Step Usage

### Run All Five Scripts

```bash
./docker/run.sh
```

### Open an Interactive Shell

Useful for experimenting with individual `tpm2_*` commands:

```bash
./docker/run.sh bash
# Inside the container you can now run, e.g.:
# tpm2_startup -c
# tpm2_getcap properties-fixed
# ./2_initial_provision.sh
```

The `TPM2TOOLS_TCTI` variable is already set inside the container, so every
`tpm2_*` command automatically targets the simulator.

### Run a Single Step

```bash
./docker/run.sh ./3_createkey.sh
```

### Use Docker Compose Directly

```bash
cd docker

# Build images
docker compose build

# Start the simulator in the background
docker compose up -d simulator

# Wait for it to be healthy, then initialise the TPM
docker compose run --rm client tpm2_startup -c

# Run individual steps
docker compose run --rm client ./2_initial_provision.sh
docker compose run --rm client ./3_createkey.sh
docker compose run --rm client ./4_createcsr.sh
docker compose run --rm client ./5_verifykey.sh

# Tear everything down
docker compose down
```

---

## What Each Script Does

The five scripts implement the full CSR attestation workflow. Here is what
happens inside each one and which TPM commands are involved.

### `1_makeCA.sh` — Create a Local Certificate Authority

No TPM interaction. Uses OpenSSL to create a self-signed root CA key and
certificate that will act as the Attestation Certification Authority (ACA).

Output:
- `ca/rootCAKey.pem` — CA private key
- `ca/rootCACert.pem` — CA self-signed certificate

### `2_initial_provision.sh` — Provision EK, SRK, and AK

Provisions the three fundamental TPM keys:

| Command | Purpose |
|---------|---------|
| `tpm2_createek` | Creates the **Endorsement Key (EK)** — the TPM's hardware identity root |
| `tpm2_createprimary` | Creates the **Storage Root Key (SRK)** — the primary storage hierarchy key |
| `tpm2_createak` | Creates the **Attestation Key (AK)** under the EK — signs attestation data |
| `tpm2_readpublic` | Exports the AK's public key in PEM format |

Then simulates an ACA issuing an AK Certificate: because a real AK cannot sign
arbitrary data (only TPM-generated structures), the script generates a
"fake" CSR with a temporary key, then uses OpenSSL's `-force_pubkey` option to
substitute the real AK public key into the final signed certificate.

Output:
- `client/ek.ctx`, `client/ek.pub` — EK context and public key
- `client/primaryStorage.ctx` — SRK context
- `client/ak.ctx`, `client/ak.pem`, `client/ak.priv` — AK context, public key, private portion
- `client/ak.cert` — AK Certificate (signed by the local CA)

### `3_createkey.sh` — Create and Attest the Application Key

Creates `key1`, the application key whose TPM residency will be proven in the CSR.

| Command | Purpose |
|---------|---------|
| `tpm2_create` | Creates `key1` under the SRK; returns its public (`TPM2B_PUBLIC`) and private (`TPM2B_PRIVATE`) blobs |
| `tpm2_load` | Loads `key1` into the TPM (needed before it can be used) |
| `tpm2_certify` | AK signs a `TPMS_ATTEST` structure containing `key1`'s **name** (a hash of its `TPMT_PUBLIC`) |
| `tpm2_readpublic` | Exports `key1`'s public key in PEM format and as a raw `TPMT_PUBLIC` binary |

The `TPMS_ATTEST` structure is the cryptographic proof that `key1` lives inside
this TPM. Because it is signed by the AK, and the AK is certified by the ACA,
the chain of trust is established.

Output:
- `client/key1.pub`, `client/key1.priv` — key blobs
- `client/key1.ctx` — loaded key context
- `client/key1.tpmSAttest` — `TPMS_ATTEST` structure (signed by AK)
- `client/key1.tpmSAttest.sig` — AK's signature over the `TPMS_ATTEST`
- `client/key1-pub.pem` — `key1` public key (PEM)
- `client/key1.tpmTPublic` — `key1` public key info (`TPMT_PUBLIC` binary)

### `4_createcsr.sh` — Build the CSR with Attestation Evidence

Assembles a PKCS #10 CSR for `key1` that contains a `id-aa-evidence` attribute
holding the TPM attestation bundle, as defined in
[draft-ietf-lamps-csr-attestation](https://datatracker.ietf.org/doc/draft-ietf-lamps-csr-attestation/).

| Step | Tool | Purpose |
|------|------|---------|
| Build `CertificationRequestInfo` | `create_cri_from_tcg_attest_certify.py` | Encodes the `TPMS_ATTEST`, signature, `TPMT_PUBLIC`, AK cert, and CA cert into ASN.1 |
| Hash the CRI | `openssl dgst` | SHA-256 digest to be signed by `key1` |
| Sign the hash | `tpm2_sign` | `key1` inside the TPM signs its own CSR's CRI |
| Attach signature | `attach_sig_to_cri.py` | Wraps the CRI and signature into a complete DER-encoded CSR |
| Convert to PEM | `openssl req` | Standard PEM output |

Output:
- `client/out.cri` — raw `CertificationRequestInfo`
- `client/out-cri.hash` — SHA-256 hash of the CRI
- `client/out-cri.sig` — AK's signature over the hash
- `client/key1-csr.der`, `client/key1-csr.pem` — the final CSR

The CSR is then "transmitted" to the verifier by copying it to `verifier/`.

### `5_verifykey.sh` — Verify the Attestation Chain

Verifies the complete attestation chain without relying on any TPM state (as a
remote verifier would operate):

1. **AK Certificate validity** — `openssl verify` against the root CA.
2. **TPM attestation signature** — `openssl dgst -verify` confirms that
   `key1.tpmSAttest` was signed by the AK whose public key is in the AK cert.
3. **Key name reconstruction** — the verifier independently computes  
   `name = 0x000b || SHA-256(TPMT_PUBLIC)` and compares it against the name
   embedded in the trusted `TPMS_ATTEST` structure. A match proves that the
   `TPMT_PUBLIC` object belongs to the same key the TPM attested.

---

## Data Flow Diagram

```
1_makeCA.sh
    └─► ca/rootCAKey.pem
    └─► ca/rootCACert.pem
             │
             ▼
2_initial_provision.sh
    TPM: tpm2_createek ──────► client/ek.ctx
    TPM: tpm2_createprimary ──► client/primaryStorage.ctx
    TPM: tpm2_createak ───────► client/ak.ctx / ak.pem
    OpenSSL: x509 -force_pubkey
             │ signs ak.pem with rootCAKey
             └──────────────────────────────► client/ak.cert
                                                   │
                                                   ▼
3_createkey.sh
    TPM: tpm2_create ────────► client/key1.pub / key1.priv
    TPM: tpm2_load ──────────► client/key1.ctx
    TPM: tpm2_certify ───────► client/key1.tpmSAttest
                               client/key1.tpmSAttest.sig  (AK signs)
    TPM: tpm2_readpublic ────► client/key1-pub.pem
                               client/key1.tpmTPublic
                                         │
                                         ▼
4_createcsr.sh
    Python: create_cri_from_tcg_attest_certify.py
            (bundles tpmSAttest + sig + tpmTPublic + ak.cert + rootCACert)
            └──────────────────────────────────────► client/out.cri
    OpenSSL dgst ──────────────────────────────────► client/out-cri.hash
    TPM: tpm2_sign (key1 signs its own CSR hash) ──► client/out-cri.sig
    Python: attach_sig_to_cri.py ─────────────────► client/key1-csr.pem
                                                          │
                   ┌──────────────────────────────────────┘
                   │ cp to verifier/
                   ▼
5_verifykey.sh
    OpenSSL verify ak.cert ──────────────────────── OK: AK is trusted
    OpenSSL dgst -verify tpmSAttest.sig ───────────── OK: TPM signed this
    SHA-256(tpmTPublic) == name-in-tpmSAttest ──────── OK: key is authentic
```

---

## Output Artefacts

After a successful run, the following key files are present on the host:

| File | Description |
|------|-------------|
| `ca/rootCACert.pem` | Self-signed root CA / ACA certificate |
| `client/ak.cert` | Attestation Key certificate (signed by root CA) |
| `client/key1.tpmSAttest` | `TPMS_ATTEST` — TPM-signed proof of `key1`'s properties |
| `client/key1.tpmSAttest.sig` | AK's signature over the `TPMS_ATTEST` |
| `client/key1.tpmTPublic` | `key1`'s `TPMT_PUBLIC` structure (key metadata + public key) |
| `client/key1-pub.pem` | `key1`'s public key in PEM format |
| **`client/key1-csr.pem`** | **The final CSR — the primary output of the example** |

---

## Differences from a Bare-Metal Run

| Aspect | Bare Metal | Docker + Simulator |
|--------|-----------|-------------------|
| TPM device | `/dev/tpm0` or `/dev/tpmrm0` | TCP socket (container hostname `simulator`) |
| TCTI setting | `device:/dev/tpmrm0` (or managed by `tpm2-abrmd`) | `mssim:host=simulator,port=2321` |
| Resource manager | `tpm2-abrmd` recommended | Not needed |
| TPM startup | Done by firmware at boot | `tpm2_startup -c` run once per container launch |
| Risk | Risk of losing real TPM assets | Zero — simulator state is ephemeral |
| Persistence | Keys survive reboot (NV storage) | Simulator state is lost when container stops |

To reset the simulator to a clean state, simply restart it:

```bash
cd docker
docker compose restart simulator
docker compose run --rm client tpm2_startup -c
```

---

## Troubleshooting

### Image build takes a long time

**Expected.** Both `tpm2-tss` and `tpm2-tools` are compiled from source so that
a version ≥ 5.7 of `tpm2-tools` is guaranteed (required for
`tpm2_print -t TPMS_ATTEST`). Subsequent runs reuse the Docker layer cache and
are fast.

### `ERROR: mssim TCTI: Failed to connect to simulator`

The client is trying to reach the simulator before it is ready. The Compose
healthcheck should prevent this, but if you are running `docker compose` commands
manually, wait a few seconds after `docker compose up -d simulator` before
running the client.

### `WARNING: The TPM returned error code ...` / `tpm2_startup` errors

If the simulator container was not fully restarted (e.g. just restarted without a
fresh `tpm2_startup -c`), the TPM may be in an inconsistent state. Run:

```bash
cd docker
docker compose restart simulator
docker compose run --rm client tpm2_startup -c
```

### Python import errors (`pyasn1`, `pyasn1_alt_modules`)

The Python dependencies are installed inside a virtual environment at
`/app/venv`. If you see import errors, confirm the `PATH` inside the container
includes `/app/venv/bin`:

```bash
./docker/run.sh bash
echo $PATH   # should contain /app/venv/bin
python3 -c "import pyasn1_alt_modules; print('ok')"
```

### Connecting to the simulator from outside Docker

To reach the simulator from your host machine (e.g. with locally installed
`tpm2-tools`), uncomment the `ports` section in `docker/docker-compose.yml`:

```yaml
    ports:
      - "2321:2321"
      - "2322:2322"
```

Then set on the host:

```bash
export TPM2TOOLS_TCTI="mssim:host=127.0.0.1,port=2321"
tpm2_startup -c
```
