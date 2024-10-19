using System;
using Org.BouncyCastle.Tls;

namespace SIPSorcery.Net;

public interface IDtlsSrtpPeer
{
    event Action<DtlsAlertLevel, DtlsAlertType, string> OnAlert;
    bool ForceUseExtendedMasterSecret { get; set; }
    SrtpPolicy GetSrtpPolicy();
    SrtpPolicy GetSrtcpPolicy();
    byte[] GetSrtpMasterServerKey();
    byte[] GetSrtpMasterServerSalt();
    byte[] GetSrtpMasterClientKey();
    byte[] GetSrtpMasterClientSalt();
    bool IsClient();
    Certificate GetRemoteCertificate();
}
