namespace SIPSorcery.Net;

public enum DtlsAlertType: byte
{
    // General alert messages
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    DecryptionFailed = 21,
    RecordOverflow = 22,
    DecompressionFailure = 30,
    HandshakeFailure = 40,
    NoCertificate = 41,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,

    // Alerts for protocol renegotiation
    ProtocolVersion = 70,
    InsufficientSecurity = 71,

    // Internal error and user-canceled events
    InternalError = 80,
    UserCanceled = 90,
    NoRenegotiation = 100,
    UnsupportedExtension = 110,

    // DTLS-specific alerts
    UnexpectedPacketLoss = 120,
    ReplayDetected = 121,

    Unknown = 255,
}
