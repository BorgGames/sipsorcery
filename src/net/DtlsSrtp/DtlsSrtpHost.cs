#nullable enable
using System;
using System.Collections.Generic;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;

namespace SIPSorcery.Net;

public class DtlsSrtpHost : DefaultTlsServer, IDtlsSrtpPeer
{
    readonly AsymmetricKeyParameter privateKey;
    readonly Certificate certificateChain;

    public RTCDtlsFingerprint Fingerprint { get; }
    public bool ForceUseExtendedMasterSecret { get; set; }
    public bool IsClient => false;
    public Certificate? RemoteCertificate { get; private set; }

    public event Action<DtlsAlertLevel, DtlsAlertType, string>? OnAlert;

    public DtlsSrtpHost(TlsCrypto crypto) : this(crypto, (Certificate?)null, null)
    {
    }

    public DtlsSrtpHost(TlsCrypto crypto, System.Security.Cryptography.X509Certificates.X509Certificate2 certificate) : this(crypto, DtlsUtils.LoadCertificateChain(crypto, certificate), DtlsUtils.LoadPrivateKeyResource(certificate))
    {
    }

    public DtlsSrtpHost(TlsCrypto crypto, string certificatePath, string keyPath) : this(crypto, new string[] { certificatePath }, keyPath)
    {
    }

    public DtlsSrtpHost(TlsCrypto crypto, string[] certificatesPath, string keyPath) :
        this(crypto, DtlsUtils.LoadCertificateChain(crypto, certificatesPath), DtlsUtils.LoadPrivateKeyResource(keyPath))
    {
    }

    public DtlsSrtpHost(TlsCrypto crypto, Certificate? certificateChain, AsymmetricKeyParameter? privateKey) : base(crypto)
    {
        if (certificateChain == null && privateKey == null)
        {
            (certificateChain, privateKey) = DtlsUtils.CreateSelfSignedTlsCert(crypto);
        }

        this.privateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
        this.certificateChain = certificateChain ?? throw new ArgumentNullException(nameof(certificateChain));

        //Generate FingerPrint
        var certificate = this.certificateChain.GetCertificateAt(0);
        Fingerprint = DtlsUtils.Fingerprint(certificate);
    }

    protected virtual void PrepareSrtpSharedSecret()
    {
        throw new NotImplementedException();
    }

    protected byte[] GetKeyingMaterial(int length)
    {
        return GetKeyingMaterial(ExporterLabel.dtls_srtp, null, length);
    }

    protected virtual byte[] GetKeyingMaterial(string asciiLabel, byte[]? context_value, int length)
    {
        throw new NotImplementedException();
    }

    #region Overrides
    public override int GetSelectedCipherSuite()
    {
        throw new NotImplementedException();
    }

    public override CertificateRequest GetCertificateRequest()
    {
        throw new NotImplementedException();
    }

    public override void NotifyClientCertificate(Certificate clientCertificate)
    {
        RemoteCertificate = clientCertificate;
    }

    public override IDictionary<int, byte[]> GetServerExtensions()
    {
        throw new NotImplementedException();
    }

    public override void ProcessClientExtensions(IDictionary<int, byte[]> clientExtensions)
    {
        base.ProcessClientExtensions(clientExtensions);

        throw new NotImplementedException();
    }

    public override void NotifyHandshakeComplete()
    {
        throw new NotImplementedException();
    }

    protected override TlsCredentialedSigner GetECDsaSignerCredentials()
    {
        throw new NotImplementedException();
    }

    protected override TlsCredentialedDecryptor GetRsaEncryptionCredentials()
    {
        throw new NotImplementedException();
    }

    protected override TlsCredentialedSigner GetRsaSignerCredentials()
    {
        throw new NotImplementedException();
    }

    public override bool RequiresExtendedMasterSecret() => ForceUseExtendedMasterSecret;

    protected override ProtocolVersion[] GetSupportedVersions()
        => [ProtocolVersion.DTLSv10, ProtocolVersion.DTLSv12];

    public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause)
    {
        base.NotifyAlertRaised(alertLevel, alertDescription, message, cause);

        throw new NotImplementedException();
    }

    public override void NotifyAlertReceived(short alertLevel, short alertDescription)
    {
        base.NotifyAlertReceived(alertLevel, alertDescription);

        throw new NotImplementedException();
    }

    public override void NotifySecureRenegotiation(bool secureRenegotiation)
    {
        throw new NotImplementedException();
    }
    #endregion Overrides
}
