import argparse
import io

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes

from pyasn1.type import univ, namedtype, constraint, tag
from pyasn1.codec.der import decoder
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc2986, rfc5280, rfc5751

# debug.setLogger(debug.Debug('all'))


# CHANGE ME once TCG assigns one.
OID_cg_attest_tpm_certify = univ.ObjectIdentifier((2, 23, 133, 20, 1))

# CHANGE ME once these is early allocation of this
# id-aa-evidence OBJECT IDENTIFIER ::= { id-aa TBDAA }
id_aa_evidence = univ.ObjectIdentifier(rfc5751.id_aa + (59,))

# Generic upper limit for ASN.1 Sequences and stuff.
MAX = 10

# RFC 9500 section 2.1
_RSA_DUMMY_KEY = serialization.load_pem_private_key("""
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsPnoGUOnrpiSqt4XynxA+HRP7S+BSObI6qJ7fQAVSPtRkqso
tWxQYLEYzNEx5ZSHTGypibVsJylvCfuToDTfMul8b/CZjP2Ob0LdpYrNH6l5hvFE
89FU1nZQF15oVLOpUgA7wGiHuEVawrGfey92UE68mOyUVXGweJIVDdxqdMoPvNNU
l86BU02vlBiESxOuox+dWmuVV7vfYZ79Toh/LUK43YvJh+rhv4nKuF7iHjVjBd9s
B6iDjj70HFldzOQ9r8SRI+9NirupPTkF5AKNe6kUhKJ1luB7S27ZkvB3tSTT3P59
3VVJvnzOjaA1z6Cz+4+eRvcysqhrRgFlwI9TEwIDAQABAoIBAEEYiyDP29vCzx/+
dS3LqnI5BjUuJhXUnc6AWX/PCgVAO+8A+gZRgvct7PtZb0sM6P9ZcLrweomlGezI
FrL0/6xQaa8bBr/ve/a8155OgcjFo6fZEw3Dz7ra5fbSiPmu4/b/kvrg+Br1l77J
aun6uUAs1f5B9wW+vbR7tzbT/mxaUeDiBzKpe15GwcvbJtdIVMa2YErtRjc1/5B2
BGVXyvlJv0SIlcIEMsHgnAFOp1ZgQ08aDzvilLq8XVMOahAhP1O2A3X8hKdXPyrx
IVWE9bS9ptTo+eF6eNl+d7htpKGEZHUxinoQpWEBTv+iOoHsVunkEJ3vjLP3lyI/
fY0NQ1ECgYEA3RBXAjgvIys2gfU3keImF8e/TprLge1I2vbWmV2j6rZCg5r/AS0u
pii5CvJ5/T5vfJPNgPBy8B/yRDs+6PJO1GmnlhOkG9JAIPkv0RBZvR0PMBtbp6nT
Y3yo1lwamBVBfY6rc0sLTzosZh2aGoLzrHNMQFMGaauORzBFpY5lU50CgYEAzPHl
u5DI6Xgep1vr8QvCUuEesCOgJg8Yh1UqVoY/SmQh6MYAv1I9bLGwrb3WW/7kqIoD
fj0aQV5buVZI2loMomtU9KY5SFIsPV+JuUpy7/+VE01ZQM5FdY8wiYCQiVZYju9X
Wz5LxMNoz+gT7pwlLCsC4N+R8aoBk404aF1gum8CgYAJ7VTq7Zj4TFV7Soa/T1eE
k9y8a+kdoYk3BASpCHJ29M5R2KEA7YV9wrBklHTz8VzSTFTbKHEQ5W5csAhoL5Fo
qoHzFFi3Qx7MHESQb9qHyolHEMNx6QdsHUn7rlEnaTTyrXh3ifQtD6C0yTmFXUIS
CW9wKApOrnyKJ9nI0HcuZQKBgQCMtoV6e9VGX4AEfpuHvAAnMYQFgeBiYTkBKltQ
XwozhH63uMMomUmtSG87Sz1TmrXadjAhy8gsG6I0pWaN7QgBuFnzQ/HOkwTm+qKw
AsrZt4zeXNwsH7QXHEJCFnCmqw9QzEoZTrNtHJHpNboBuVnYcoueZEJrP8OnUG3r
UjmopwKBgAqB2KYYMUqAOvYcBnEfLDmyZv9BTVNHbR2lKkMYqv5LlvDaBxVfilE0
2riO4p6BaAdvzXjKeRrGNEKoHNBpOSfYCOM16NjL8hIZB1CaV3WbT5oY+jp7Mzd5
7d56RZOE+ERK2uz/7JX9VSsM/LbH9pJibd4e8mikDS9ntciqOH/3
-----END RSA PRIVATE KEY-----
""".encode(), password=None)


TPM_S_ATTEST = 'tpmSAttest'
TPM_S_ATTEST_ARG = TPM_S_ATTEST.lower()

SIGNATURE = 'signature'
SIGNATURE_ARG = SIGNATURE.lower()

TPM_T_PUBLIC = 'tpmTPublic'
TPM_T_PUBLIC_ARG = TPM_T_PUBLIC.lower()


parser = argparse.ArgumentParser()
parser.add_argument(TPM_S_ATTEST_ARG, type=argparse.FileType('rb'))
parser.add_argument(SIGNATURE_ARG, type=argparse.FileType('rb'))
parser.add_argument(TPM_T_PUBLIC_ARG, type=argparse.FileType('rb'))
parser.add_argument('publickeyfilepem', type=argparse.FileType('rb'))
parser.add_argument('akCertChain', type=argparse.FileType('r'), nargs='+')
parser.add_argument(
    '--extra-attribute',
    action='store_true',
    default=False,
    help='Negative example: append a second bogus challengePassword attribute to the CSR attributes',
)
parser.add_argument(
    '--bad-tpm-signature',
    action='store_true',
    default=False,
    help='Negative example: corrupt the first byte of the TPM attestation signature (outer CSR signature remains valid)',
)

args = parser.parse_args()
args_vars = vars(args)


# from draft-ietf-lamps-csr-attestation section A.2
# Tcg-attest-certify ::= SEQUENCE {
#   tpmSAttest       OCTET STRING,
#   signature        OCTET STRING,
#   tpmTPublic       OCTET STRING OPTIONAL
# }
class TcgAttestCertify(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(TPM_S_ATTEST, univ.OctetString()),
        namedtype.NamedType(SIGNATURE, univ.OctetString()),
        namedtype.OptionalNamedType(TPM_T_PUBLIC, univ.OctetString()),
    )


STATEMENT_MAPPINGS = {
    OID_cg_attest_tpm_certify: TcgAttestCertify(),
}

# ---------------------------------------------------------------------------
# AttestAttrSet / Attributes helper
# ---------------------------------------------------------------------------


# AttestAttrSet ATTRIBUTE ::= { ... }  -- None defined in this document
# Modelled as a SET OF ANY to accept any attribute without constraining the
# open type at the pyasn1 level.
# draft-ietf-lamps-csr-attestation-22, Section 4.1
class AttestAttrSet(univ.SetOf):
    """Set of additional attributes for an AttestationStatement (open type)."""

    componentType = rfc2986.Attribute()


# ---------------------------------------------------------------------------
# OtherCertificateFormat
# ---------------------------------------------------------------------------


# OtherCertificateFormat ::= SEQUENCE {
#     otherCertFormat  OTHER-CERT-FMT.&id({SupportedCertFormats}),
#     otherCert        OTHER-CERT-FMT.&Type({SupportedCertFormats}{@otherCertFormat})
# }
# draft-ietf-lamps-csr-attestation-22, Section 4.1 (reproduced from RFC 6268)
class OtherCertificateFormat(univ.Sequence):
    """Non-X.509 certificate format wrapper (open type, OID + content)."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("otherCertFormat", univ.ObjectIdentifier()),
        namedtype.NamedType("otherCert", univ.Any()),
    )


# ---------------------------------------------------------------------------
# LimitedCertChoices
# ---------------------------------------------------------------------------


# LimitedCertChoices ::= CertificateChoices
#   (WITH COMPONENTS { certificate, other })
#
# This is CertificateChoices restricted to only 'certificate' and 'other'
# (i.e. extendedCertificate, v1AttrCert, v2AttrCert are excluded).
# draft-ietf-lamps-csr-attestation-22, Section 4.1
class LimitedCertChoices(univ.Choice):
    """CertificateChoices restricted to 'certificate' and 'other'."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("certificate", rfc5280.Certificate()),
        namedtype.NamedType(
            "other",
            OtherCertificateFormat().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatConstructed,
                    3,
                )
            ),
        ),
    )


# ---------------------------------------------------------------------------
# AttestationStatement
# ---------------------------------------------------------------------------


# AttestationStatement ::= SEQUENCE {
#     type           ATTESTATION-STATEMENT.&id({AttestationStatementSet}),
#     bindsPublicKey [0] BOOLEAN DEFAULT TRUE,
#     stmt           ATTESTATION-STATEMENT.&Type(
#                        {AttestationStatementSet}{@type}),
#     attrs          [1] Attributes {{AttestAttrSet}} OPTIONAL
# }
# draft-ietf-lamps-csr-attestation-22, Section 4.1, Figure 1
class AttestationStatement(univ.Sequence):
    """Single attestation statement (Evidence, Endorsement, or AR)."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", univ.ObjectIdentifier()),
        namedtype.DefaultedNamedType(
            "bindsPublicKey",
            univ.Boolean(True).subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple,
                    0,
                )
            ),
        ),
        namedtype.NamedType("stmt", univ.Any()),
        namedtype.OptionalNamedType(
            "attrs",
            AttestAttrSet().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatConstructed,
                    1,
                )
            ),
        ),
    )


# ---------------------------------------------------------------------------
# AttestationBundle
# ---------------------------------------------------------------------------


# Helper: SEQUENCE SIZE (1..MAX) OF AttestationStatement
# draft-ietf-lamps-csr-attestation-22, Section 4.1, Figure 2
class _AttestationSequence(univ.SequenceOf):
    componentType = AttestationStatement()
    subtypeSpec = constraint.ValueSizeConstraint(1, float("inf"))


# Helper: SEQUENCE SIZE (1..MAX) OF LimitedCertChoices
# draft-ietf-lamps-csr-attestation-22, Section 4.1, Figure 2
class _CertSequence(univ.SequenceOf):
    componentType = LimitedCertChoices()
    subtypeSpec = constraint.ValueSizeConstraint(1, float("inf"))


# AttestationBundle ::= SEQUENCE {
#     attestations  SEQUENCE SIZE (1..MAX) OF AttestationStatement,
#     certs         SEQUENCE SIZE (1..MAX) OF LimitedCertChoices OPTIONAL
# }
# draft-ietf-lamps-csr-attestation-22, Section 4.1, Figure 2
class AttestationBundle(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("attestations", _AttestationSequence()),
        namedtype.OptionalNamedType("certs", _CertSequence()),
    )


# Construct an Tcg-attest-certify as per draft-ietf-lamps-csr-attestation appendix A.2
tcg_csr_certify = TcgAttestCertify()
tcg_csr_certify[TPM_S_ATTEST] = args_vars[TPM_S_ATTEST_ARG].read()
_sig_bytes = args_vars[SIGNATURE_ARG].read()
if args.bad_tpm_signature:
    # Flip the first byte to produce an invalid TPM attestation signature while
    # leaving the outer PKCS#10 signature (computed over the whole CRI) correct.
    _sig_bytes = bytes([_sig_bytes[0] ^ 0xFF]) + _sig_bytes[1:]
tcg_csr_certify[SIGNATURE] = _sig_bytes
tcg_csr_certify[TPM_T_PUBLIC] = args_vars[TPM_T_PUBLIC_ARG].read()

# tcg_csr_certify_der = encode(tcg_csr_certify)

# Construct an EvidenceStatement
attestation_statement = AttestationStatement()
attestation_statement["type"] = OID_cg_attest_tpm_certify
attestation_statement["stmt"] = tcg_csr_certify

# Construct an EvidenceBundle
attestation_bundle = AttestationBundle()
attestation_bundle["attestations"].append(attestation_statement)


def _parse_certs_to_limited_choices(
        cert_list: list[rfc5280.Certificate],
) -> list[LimitedCertChoices]:
    """Convert a list of X.509 certificates to a list of `LimitedCertChoices` with the 'certificate' option."""
    out = []
    for x in cert_list:
        if isinstance(x, rfc5280.Certificate):
            out.append(LimitedCertChoices().setComponentByName("certificate", x))
        elif isinstance(x, OtherCertificateFormat):
            out.append(LimitedCertChoices().setComponentByName("other", x))
        elif isinstance(x, LimitedCertChoices):
            out.append(x)
        else:
            raise TypeError(f"Unexpected type {type(x)} in list of certificates")
    return out


certs = []
for certFile in args_vars["akCertChain"]:
    print("certFile: " + str(certFile))

    substrate = pem.readPemFromFile(certFile)
    if substrate == "":
        print("File " + certFile.name + " could not be read as PEM. Skipping")
        continue

    certificate, rest = decoder.decode(
        io.BytesIO(substrate), asn1Spec=rfc5280.Certificate()
    )
    certs.append(certificate)

attestation_bundle["certs"].extend(_parse_certs_to_limited_choices(certs))


# Construct an attr-evidence
# -- For PKCS#10
# attr-evidence ATTRIBUTE ::= {
#   TYPE EvidenceBundles
#   IDENTIFIED BY id-aa-evidence
# }
attr_evidence = rfc5280.Attribute()
attr_evidence["type"] = id_aa_evidence
attr_evidence["values"].append(attestation_bundle)


csr_builder = x509.CertificateSigningRequestBuilder()
csr_builder = csr_builder.subject_name(x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'ZZ'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Province'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, 'Locality'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'ietf-lamps'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'ietf-lamps-csr'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'test-key1')
    ]
))

# csr_builder.add_attribute(id_aa_evidence_cryptagraphy, evidenceBundles)

csr = csr_builder.sign(_RSA_DUMMY_KEY, hashes.SHA256())

# Extract the CertificateRequestInfo (ie throw away the signature)
cri_der = csr.tbs_certrequest_bytes
cri_pyasn1, _ = decode(cri_der, rfc2986.CertificationRequestInfo())

# Add in the evidence attribute.
cri_pyasn1['attributes'].append(attr_evidence)

# Negative example: append the id-aa-evidence attribute a second time.
if args.extra_attribute:
    cri_pyasn1['attributes'].append(attr_evidence)

# Swap out the dummy public key for the TPM-controlled one
pubkey = serialization.load_pem_public_key(args.publickeyfilepem.read())
pubkey_der = pubkey.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

spki, _ = decode(pubkey_der, rfc5280.SubjectPublicKeyInfo())
cri_pyasn1['subjectPKInfo']['subjectPublicKey'] = spki['subjectPublicKey']

if args.bad_tpm_signature:
    output_filename = 'out-neg-bad-tpm-sig.cri'
elif args.extra_attribute:
    output_filename = 'out-neg-extra-attr.cri'
else:
    output_filename = 'out.cri'

with open(output_filename, 'wb') as f:
    f.write(encode(cri_pyasn1))
