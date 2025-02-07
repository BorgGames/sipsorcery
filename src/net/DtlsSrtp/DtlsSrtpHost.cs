#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

// credits: Claude 3.5

namespace SIPSorcery.Net;

public class DtlsSrtpHost : DefaultTlsServer, IDtlsSrtpPeer
{
    readonly AsymmetricKeyParameter privateKey;
    readonly Certificate certificateChain;

    public RTCDtlsFingerprint Fingerprint { get; }
    public bool ForceUseExtendedMasterSecret { get; set; }
    public bool IsClient => false;
    public Certificate? RemoteCertificate { get; private set; }

    public byte[]? SrtpMasterClientKey { get; private set; }
    public byte[]? SrtpMasterServerKey { get; private set; }
    public byte[]? SrtpMasterClientSalt { get; private set; }
    public byte[]? SrtpMasterServerSalt { get; private set; }
    public SrtpPolicy? SrtpPolicy { get; private set; }
    public SrtpPolicy? SrtcpPolicy { get; private set; }

    public event Action<DtlsAlertLevel, DtlsAlertType, string>? OnAlert;

    public DtlsSrtpHost(TlsCrypto crypto) : this(crypto, (Certificate?)null, null)
    {
    }

    public DtlsSrtpHost(TlsCrypto crypto, System.Security.Cryptography.X509Certificates.X509Certificate2 certificate) :
        this(crypto, DtlsUtils.LoadCertificateChain(crypto, certificate), DtlsUtils.LoadPrivateKeyResource(certificate))
    {
    }

    public DtlsSrtpHost(TlsCrypto crypto, string certificatePath, string keyPath) : this(crypto,
        new string[] { certificatePath }, keyPath)
    {
    }

    public DtlsSrtpHost(TlsCrypto crypto, string[] certificatesPath, string keyPath) :
        this(crypto, DtlsUtils.LoadCertificateChain(crypto, certificatesPath),
            DtlsUtils.LoadPrivateKeyResource(keyPath))
    {
    }

    public DtlsSrtpHost(TlsCrypto crypto, Certificate? certificateChain, AsymmetricKeyParameter? privateKey) :
        base(crypto)
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

    #region SRTP Constants

    private static class SrtpConstants
    {
        public const int KEY_LENGTH = 16;
        public const int SALT_LENGTH = 14;
        public const int MASTER_LENGTH = KEY_LENGTH + SALT_LENGTH;

        public static readonly int[] PROTECTION_PROFILES =
        {
            SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80,
        };
    }

    #endregion

    // Add properties for SRTP state tracking
    private int? negotiatedSrtpProfile;
    private bool isHandshakeComplete;

    protected virtual void PrepareSrtpSharedSecret()
    {
        if (m_context == null || !isHandshakeComplete)
        {
            throw new InvalidOperationException("DTLS handshake not complete");
        }

        var keyingMaterialLength = IsUsingAesGcm()
            ? (2 * (SrtpConstants.KEY_LENGTH + SrtpConstants.SALT_LENGTH))
            : (2 * SrtpConstants.MASTER_LENGTH);

        var srtpMaterial = GetKeyingMaterial(ExporterLabel.dtls_srtp, null, keyingMaterialLength);

        ExtractKeys(srtpMaterial);
        ConfigureSrtpPolicies();
    }

    private void ExtractKeys(byte[] srtpMaterial)
    {
        SrtpMasterClientKey = new byte[SrtpConstants.KEY_LENGTH];
        SrtpMasterServerKey = new byte[SrtpConstants.KEY_LENGTH];
        SrtpMasterClientSalt = new byte[SrtpConstants.SALT_LENGTH];
        SrtpMasterServerSalt = new byte[SrtpConstants.SALT_LENGTH];

        Buffer.BlockCopy(srtpMaterial, 0, SrtpMasterClientKey, 0, SrtpConstants.KEY_LENGTH);
        Buffer.BlockCopy(srtpMaterial, SrtpConstants.KEY_LENGTH, SrtpMasterClientSalt, 0, SrtpConstants.SALT_LENGTH);
        Buffer.BlockCopy(srtpMaterial, SrtpConstants.MASTER_LENGTH, SrtpMasterServerKey, 0, SrtpConstants.KEY_LENGTH);
        Buffer.BlockCopy(srtpMaterial, SrtpConstants.MASTER_LENGTH + SrtpConstants.KEY_LENGTH, SrtpMasterServerSalt, 0,
            SrtpConstants.SALT_LENGTH);
    }

    protected virtual byte[] GetKeyingMaterial(string asciiLabel, byte[]? context_value, int length)
    {
        if (m_context == null)
        {
            throw new InvalidOperationException("DTLS context not established");
        }

        return m_context.ExportKeyingMaterial(asciiLabel, context_value, length);
    }

    public override CertificateRequest GetCertificateRequest()
    {
        var certificateTypes = new short[]
        {
            ClientCertificateType.ecdsa_sign,
            ClientCertificateType.rsa_sign
        };

        var sigAlgs = new[]
        {
            new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa),
            new SignatureAndHashAlgorithm(HashAlgorithm.sha384, SignatureAlgorithm.ecdsa),
            SignatureAndHashAlgorithm.rsa_pss_rsae_sha256
        };

        return new CertificateRequest(certificateTypes, sigAlgs, null);
    }

    public override IDictionary<int, byte[]> GetServerExtensions()
    {
        var extensions = base.GetServerExtensions() ?? new Dictionary<int, byte[]>();

        // Create matching SRTP data structure
        var useSrtpData = new UseSrtpData(
            SrtpConstants.PROTECTION_PROFILES,
            [] // We should echo the client's MKI or stay empty consistently
        );

        // Add it using the same utility the client uses to read it
        TlsSrtpUtilities.AddUseSrtpExtension(extensions, useSrtpData);

        return extensions;
    }

    public override void ProcessClientExtensions(IDictionary<int, byte[]> clientExtensions)
    {
        base.ProcessClientExtensions(clientExtensions);

        var clientProfiles = TlsSrtpUtilities.GetUseSrtpExtension(clientExtensions);
        if (clientProfiles is null)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure, "SRTP extension required");
        }

        negotiatedSrtpProfile = NegotiateSrtpProfile(clientProfiles);

        if (!negotiatedSrtpProfile.HasValue)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure, "No matching SRTP profile");
        }
    }

    private int? NegotiateSrtpProfile(UseSrtpData clientProfiles)
    {
        return SrtpConstants.PROTECTION_PROFILES
            .FirstOrDefault(profile => clientProfiles.ProtectionProfiles.Contains(profile));
    }

    public override void NotifyHandshakeComplete()
    {
        base.NotifyHandshakeComplete();
        isHandshakeComplete = true;
        PrepareSrtpSharedSecret();
    }

    public override void NotifyClientCertificate(Certificate clientCertificate)
    {
        RemoteCertificate = clientCertificate;
    }

    private void ConfigureSrtpPolicies()
    {
        if (!negotiatedSrtpProfile.HasValue)
        {
            throw new InvalidOperationException("No SRTP profile negotiated");
        }

        var srtpParams = SrtpParameters.GetSrtpParametersForProfile(negotiatedSrtpProfile.Value);

        SrtpPolicy = srtpParams.GetSrtpPolicy();
        SrtcpPolicy = srtpParams.GetSrtcpPolicy();
    }

    private bool IsUsingAesGcm() =>
        negotiatedSrtpProfile == SrtpProtectionProfile.SRTP_AEAD_AES_256_GCM ||
        negotiatedSrtpProfile == SrtpProtectionProfile.SRTP_AEAD_AES_128_GCM;

    protected override TlsCredentialedSigner GetECDsaSignerCredentials()
    {
        var cryptoParams = new TlsCryptoParameters(m_context);
        var algorithm = new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa);
        return new BcDefaultTlsCredentialedSigner(cryptoParams, (BcTlsCrypto)Crypto, privateKey, certificateChain,
            algorithm);
    }

    public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause)
    {
        base.NotifyAlertRaised(alertLevel, alertDescription, message, cause);
        OnAlert?.Invoke((DtlsAlertLevel)alertLevel, (DtlsAlertType)alertDescription, message);
    }

    public override void NotifyAlertReceived(short alertLevel, short alertDescription)
    {
        base.NotifyAlertReceived(alertLevel, alertDescription);
        OnAlert?.Invoke((DtlsAlertLevel)alertLevel, (DtlsAlertType)alertDescription, "Alert received");
    }

    public override void NotifySecureRenegotiation(bool secureRenegotiation)
    {
        if (!secureRenegotiation)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure, "Secure renegotiation required");
        }
    }

    public override bool RequiresExtendedMasterSecret() => ForceUseExtendedMasterSecret;

    protected override ProtocolVersion[] GetSupportedVersions() => [ProtocolVersion.DTLSv12];

    protected override int[] GetSupportedCipherSuites() =>
    [
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_AES_256_GCM_SHA384,
        CipherSuite.TLS_AES_128_GCM_SHA256,
    ];

    public override int[] GetSupportedGroups() => [NamedGroup.secp256r1];
}
