# CLAUDE.md

## Project Overview

This project demonstrates how to create a Certificate Signing Request (CSR) with cryptographic proof that a key is stored within a Trusted Platform Module (TPM 2.0), implementing [draft-ietf-lamps-csr-attestation](https://datatracker.ietf.org/doc/draft-ietf-lamps-csr-attestation/).

## Workflow

Scripts must be executed in order:

```
1_makeCA.sh           → Create root CA (no TPM)
2_initial_provision.sh → Provision EK, SRK, AK in TPM; create AK cert
3_createkey.sh        → Create key1 in TPM; generate attestation data
4_createcsr.sh        → Build CSR with id-aa-evidence attribute
5_verifykey.sh        → Verify attestation chain; issue certificate
0_clean.sh            → Clean generated artifacts (optional)
```

## Running the Project

**Docker (recommended — no physical TPM required):**
```bash
./docker/run.sh              # Run full workflow
./docker/run.sh bash         # Interactive shell
./docker/run.sh ./3_createkey.sh  # Run a single script
```

**Bare metal (physical TPM — risky, test in Docker first):**
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
# Also install: https://github.com/russhousley/pyasn1-alt-modules
./1_makeCA.sh && ./2_initial_provision.sh && ./3_createkey.sh && ./4_createcsr.sh && ./5_verifykey.sh
```

## Key Dependencies

- `tpm2-tools` v5.7+ (must be built from source for `tpm2_print -t TPMS_ATTEST`)
- `tpm2-tss` v4.1.3+
- `openssl`
- Python: `pyasn1`, `pyasn1_modules`, `pyasn1-alt-modules` (fork), `cryptography`

## Directory Layout

Defined in `dirs.sh` (sourced by all scripts):
- `ca/` — CA key and certificate
- `client/` — TPM contexts, key blobs, attestation structures, CSR
- `verifier/` — Verification artifacts and issued certificate

## Key Files

| File                                    | Role                                                       |
|-----------------------------------------|------------------------------------------------------------|
| `dirs.sh`                               | Exports `cadir`, `cdir`, `vdir` path variables             |
| `create_cri_from_tcg_attest_certify.py` | Encodes TPM structures into ASN.1 CertificationRequestInfo |
| `attach_sig_to_cri.py`                  | Wraps CRI + signature into PKCS#10 CSR (DER)               |
| `openssl-*.conf`                        | OpenSSL configs for CA, AK, and key1 certificates          |
| `docs/tpm-example.md`                   | IETF spec excerpt with OIDs and TPM structure definitions  |

## Environment

In Docker, `TPM2TOOLS_TCTI=mssim:host=simulator,port=2321` is set automatically.
On bare metal with tpm2-abrmd: user must be in the `tss` group.

## Conventions

- Shell scripts use `set -e` and source `dirs.sh` for paths
- TPM binary structures use extensions: `.ctx`, `.pub`, `.priv`, `.tpmSAttest`, `.tpmTPublic`
- Key identifiers: `ek` (Endorsement Key), `ak` (Attestation Key), `key1` (application key)
- Python uses pyasn1 class hierarchy matching RFC specs; OIDs as integer tuples
- Test DN uses `C=ZZ, O=ietf-lamps` (ZZ is a placeholder country code)

## Security Warning

**Do not run on a production bare-metal TPM without understanding the risks.** TPM operations can affect OS boot integrity and may overwrite existing keys. Always use the Docker simulator for development and testing.