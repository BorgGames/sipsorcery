using System;
using Org.BouncyCastle.Tls;

// credits: Claude 3.5

namespace SIPSorcery.Net;

public struct SrtpParameters
{
    // http://tools.ietf.org/html/rfc5764#section-4.1.2
    public static readonly SrtpParameters SRTP_AEAD_AES_128_GCM = new SrtpParameters(SrtpProtectionProfile.SRTP_AEAD_AES_128_GCM, SrtpPolicy.AEAD_AES_128_GCM_ENCRYPTION, 16, SrtpPolicy.AEAD_AES_128_GCM_AUTHENTICATION, 16, 8, 8, 12);
    public static readonly SrtpParameters SRTP_AES128_CM_HMAC_SHA1_80 = new SrtpParameters(SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80, SrtpPolicy.AESCM_ENCRYPTION, 16, SrtpPolicy.HMACSHA1_AUTHENTICATION, 20, 10, 10, 14);
    public static readonly SrtpParameters SRTP_AES128_CM_HMAC_SHA1_32 = new SrtpParameters(SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32, SrtpPolicy.AESCM_ENCRYPTION, 16, SrtpPolicy.HMACSHA1_AUTHENTICATION, 20, 4, 10, 14);
    public static readonly SrtpParameters SRTP_NULL_HMAC_SHA1_80 = new SrtpParameters(SrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_80, SrtpPolicy.NULL_ENCRYPTION, 0, SrtpPolicy.HMACSHA1_AUTHENTICATION, 20, 10, 10, 0);
    public static readonly SrtpParameters SRTP_NULL_HMAC_SHA1_32 = new SrtpParameters(SrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_32, SrtpPolicy.NULL_ENCRYPTION, 0, SrtpPolicy.HMACSHA1_AUTHENTICATION, 20, 4, 10, 0);

    private readonly int profile;
    private readonly int encType;
    private readonly int encKeyLength;
    private readonly int authType;
    private readonly int authKeyLength;
    private readonly int authTagLength;
    private readonly int rtcpAuthTagLength;
    private readonly int saltLength;

    private SrtpParameters(int newProfile, int newEncType, int newEncKeyLength, int newAuthType, int newAuthKeyLength, int newAuthTagLength, int newRtcpAuthTagLength, int newSaltLength)
    {
        profile = newProfile;
        encType = newEncType;
        encKeyLength = newEncKeyLength;
        authType = newAuthType;
        authKeyLength = newAuthKeyLength;
        authTagLength = newAuthTagLength;
        rtcpAuthTagLength = newRtcpAuthTagLength;
        saltLength = newSaltLength;
    }

    public int GetProfile()
    {
        return profile;
    }

    public int GetCipherKeyLength()
    {
        return encKeyLength;
    }

    public int GetCipherSaltLength()
    {
        return saltLength;
    }

    /// <param name="profileValue"><seealso cref="SrtpProtectionProfile"/></param>
    public static SrtpParameters GetSrtpParametersForProfile(int profileValue)
    {
        switch (profileValue)
        {
            case SrtpProtectionProfile.SRTP_AEAD_AES_128_GCM:
                return SRTP_AEAD_AES_128_GCM;
            case SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80:
                return SRTP_AES128_CM_HMAC_SHA1_80;
            case SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32:
                return SRTP_AES128_CM_HMAC_SHA1_32;
            case SrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_80:
                return SRTP_NULL_HMAC_SHA1_80;
            case SrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_32:
                return SRTP_NULL_HMAC_SHA1_32;
            default:
                throw new ArgumentException($"Unsupported SRTP protection profile {profileValue}.");
        }
    }

    public SrtpPolicy GetSrtpPolicy()
    {
        return new SrtpPolicy(encType, encKeyLength, authType, authKeyLength, authTagLength, saltLength);
    }

    public SrtpPolicy GetSrtcpPolicy()
    {
        return new SrtpPolicy(encType, encKeyLength, authType, authKeyLength, rtcpAuthTagLength, saltLength);
    }
}