#!/bin/bash
. ./dirs.sh
set -e

#
# Filenames
# key1.pub            : key1 public key information     : TPM2B_PUBLIC structure
# key1-pub.pem        : key1 public key                 : PEM format
# key1.priv           : key1 private key                : TPM2B_PRIVATE structure
# key1.tpmTPublic     : key1 public key information     : TPMT_PUBLIC structure
# key1.tpmSAttest     : key1 attestation structure      : TPMS_ATTEST structure
# key1.tpmSAttest.sig : signature over key1.tpmSAttest
# key1-csr.pem                 : positive example CSR             : PEM format
# key1-neg-extra-attr-csr.pem  : negative example: extra attribute : PEM format
# key1-neg-bad-tpm-sig-csr.pem : negative example: bad TPM sig    : PEM format
#

# Build and sign a single CSR variant.
#   $1 : variant label, e.g. "" | "neg-extra-attr" | "neg-bad-tpm-sig"
#   $2 : optional Python flag, e.g. "" | "--extra-attribute" | "--bad-tpm-signature"
create_csr_variant() {
    local label="$1"
    local py_flag="$2"

    # Derive file-name prefixes from the label.
    local cri_prefix csr_prefix
    if [ -z "$label" ]; then
        cri_prefix="out"
        csr_prefix="key1"
    else
        cri_prefix="out-${label}"
        csr_prefix="key1-${label}"
    fi

    # Build the argument list; append the flag only when non-empty.
    local py_args=($cdir/key1.tpmSAttest $cdir/key1.tpmSAttest.sig $cdir/key1.tpmTPublic \
                   $cdir/key1-pub.pem $cdir/ak.cert $cadir/rootCACert.pem)
    [ -n "$py_flag" ] && py_args+=("$py_flag")

    # Wrap the TPM data into an ASN.1 CertificationRequestInfo.
    python3 create_cri_from_tcg_attest_certify.py "${py_args[@]}"
    mv "${cri_prefix}.cri" "$cdir/${cri_prefix}.cri"

    openssl dgst -sha256 -binary -out "$cdir/${cri_prefix}-cri.hash" "$cdir/${cri_prefix}.cri"

    # Sign the CRI hash with key1 via the TPM.
    # The outer CSR signature is always correct; only inner content may differ.
    echo -e "\n   *** Signing ${cri_prefix}.cri with key1 (TPM) ***"
    tpm2_sign -c $cdir/key1.ctx -g sha256 -d "$cdir/${cri_prefix}-cri.hash" -f plain \
              -o "$cdir/${cri_prefix}-cri.sig"
    # Free transient objects; later steps are OpenSSL/Python only.
    tpm2_flushcontext --transient-object

    python3 attach_sig_to_cri.py "$cdir/${cri_prefix}.cri" "$cdir/${cri_prefix}-cri.sig"
    mv out.csr "$cdir/${csr_prefix}-csr.der"

    # Verify outer signature (always expected to pass, even for negative examples).
    openssl req -noout -verify -inform der -in "$cdir/${csr_prefix}-csr.der"

    # Convert to PEM and publish to verifier.
    openssl req -inform der -in "$cdir/${csr_prefix}-csr.der" -out "$cdir/${csr_prefix}-csr.pem"
    cp "$cdir/${csr_prefix}-csr.pem" "$vdir"
}

# Positive example.
create_csr_variant "" ""

# Negative example 1: CSR contains a second, unexpected attribute.
create_csr_variant "neg-extra-attr" "--extra-attribute"

# Negative example 2: TPM attestation signature is corrupted (outer CSR sig remains valid).
create_csr_variant "neg-bad-tpm-sig" "--bad-tpm-signature"
