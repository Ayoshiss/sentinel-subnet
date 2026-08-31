"""
Real AMD SEV-SNP attestation.

Where `sentinel.attestation.MockSilicon` simulates the shape of hardware
attestation, this package handles the real thing: parsing the binary report a
SEV-SNP guest produces, and verifying it against AMD's published certificate
chain.

The work splits cleanly in two, and only one half needs hardware to *run*:

    report generation   ioctl to /dev/sev-guest      needs an EPYC CVM
    report verification parse + validate cert chain  needs nothing

Both halves are done and confirmed on real silicon (AMD EPYC 7B13, 2026-08-31).
A genuine report and AMD's real certificate chain are committed under
`tests/fixtures/`, so the end-to-end verification runs in CI and can be checked
by anyone without hardware.

Bringing generation up on real silicon was not the formality it looked like. The
ioctl number was wrong, the kernel reports a short certificate buffer through a
different errno than its header implies, and the certificate table's GUID
byte order was the opposite of what was assumed — with a unit test that had been
written under the same assumption and therefore passed. Encoding tests written
alongside the code they test are not an independent check of it.
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
from .certtable import KNOWN_GUIDS, CertTableError, der_to_pem, parse_cert_table
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
    # host certificate table (extended report)
    "parse_cert_table",
    "CertTableError",
    "der_to_pem",
    "KNOWN_GUIDS",
    # verifier
    "SevSnpVerifier",
    "SevSnpPolicy",
]
