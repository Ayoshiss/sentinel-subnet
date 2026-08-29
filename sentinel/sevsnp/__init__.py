"""
Real AMD SEV-SNP attestation.

Where `sentinel.attestation.MockSilicon` simulates the shape of hardware
attestation, this package handles the real thing: parsing the binary report a
SEV-SNP guest produces, and verifying it against AMD's published certificate
chain.

The work splits cleanly in two, and only one half needs hardware:

    report generation   ioctl to /dev/sev-guest      needs an EPYC CVM
    report verification parse + validate cert chain  needs nothing

Verification is the larger half and it is built here, offline, against AMD's
actual root certificates. Generation is roughly fifty lines and lands once a
confidential VM is available.
"""

from .certs import (
    PRODUCTS,
    CertChain,
    CertificateError,
    fetch_cert_chain,
    fetch_vcek,
    load_cert_chain,
    verify_vcek,
)
from .report import (
    REPORT_SIZE,
    SIGNATURE_OFFSET,
    AttestationReportBlob,
    ReportParseError,
    TcbVersion,
    parse_report,
)
from .verifier import SevSnpPolicy, SevSnpVerifier

__all__ = [
    # report
    "AttestationReportBlob",
    "ReportParseError",
    "TcbVersion",
    "parse_report",
    "REPORT_SIZE",
    "SIGNATURE_OFFSET",
    # certs
    "CertChain",
    "CertificateError",
    "fetch_cert_chain",
    "load_cert_chain",
    "fetch_vcek",
    "verify_vcek",
    "PRODUCTS",
    # verifier
    "SevSnpVerifier",
    "SevSnpPolicy",
]
