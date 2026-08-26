package com.muthuopensource.service;


import com.muthuopensource.utils.CryptoUtil;
import com.muthuopensource.utils.ServerUtils;
import com.muthuopensource.utils.SystemConfiguration;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.jce.ECPointUtil;

import javax.crypto.KeyAgreement;

import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

public class PlatformSSOKeyService {

    private static PlatformSSOKeyService instance = null;

    public static PlatformSSOKeyService getInstance(){
        if (instance==null){
            instance = new PlatformSSOKeyService();
        }
        return instance;
    }

    public JWEObject performPSSOKeyRequest(String serialNumber, Base64URL partyVInfo,String userName,String keyPurpose) throws Exception {

        //1:Generating KeyPair and Self Signed Certificate
        KeyPair keyPair = CryptoUtil.generateECKeyPair("secp256r1");
        X509Certificate certificate = CryptoUtil.generateSelfSignedCertificate(serialNumber,keyPair);

        ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        ECKey ecKeyPair = new ECKey.Builder(Curve.P_256, ecPublicKey)
                .privateKey(ecPrivateKey)
                .build();

        //2:Setting key_context as JWE which contains the user assigned Private ECKey protected with secret stored in server
        //  Constructing the Payload for JWE Response as Indicated in PSSO Key Response Structure
        //https://developer.apple.com/documentation/authenticationservices/supporting-key-requests-and-key-exchange-requests#Create-the-key-response-JSON-Web-Encryption-JWE
        Payload payload = new Payload(Map.of(
                "certificate", Base64.getUrlEncoder().encodeToString(certificate.getEncoded()),
                "exp",certificate.getNotBefore().toInstant().plusSeconds(300).getEpochSecond(), // 5 Minutes from Now
                "iat",certificate.getNotBefore().toInstant().getEpochSecond(),
                "key_context",getServerEncryptedKeyContext(ecKeyPair).serialize()));

        //6:Generating JWE with Device's Encryption Key and the Payload as Indicated in PSSO Key Response Structure
        //https://developer.apple.com/documentation/authenticationservices/supporting-key-requests-and-key-exchange-requests#Create-the-key-response-JSON-Web-Encryption-JWE
        return CryptoUtil.generateJWE("platformsso-key-response+jwt",
                ECKey.parse(PlatformSSODeviceService.getInstance().getDeviceEncryptionKey(serialNumber)),
                partyVInfo,
                payload);
    }


    public JWEObject performPSSOKeyExchange(String serialNumber,Base64URL otherPublicKeyx9_62, Base64URL partyVInfo,String keyContext) throws Exception {

        //1: Decrypting KeyContext to get User Assinged Private ECKey
        ECKey senderPrivateKey = getDecryptedKeyContext(JWEObject.parse(keyContext));

        //2:Building the Other Party's Public Key from the x9.62 Encoded Byte Sequence and Constructing Other Party Public Key
        ECPoint otherPublicECPoint = ECPointUtil.decodePoint(Curve.P_256.toECParameterSpec().getCurve(), otherPublicKeyx9_62.decode());
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(otherPublicECPoint, Curve.P_256.toECParameterSpec());
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        ECPublicKey otherPublicKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);
        ECKey otherPartyPublicKey = new ECKey.Builder(Curve.P_256, otherPublicKey)
                .build();

        //3:Deriving the Shared Secret using ECDH Key Agreement Protocol
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(senderPrivateKey.toPrivateKey());
        keyAgreement.doPhase(otherPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        Instant jweIssuedTime = Instant.now();

        //4:Constructing the Payload for JWE Response as Indicated in PSSO Key Exchange Response Structure
        Payload payload = new Payload(Map.of(
                "key", Base64.getEncoder().encodeToString(sharedSecret),
                "exp",jweIssuedTime.plusSeconds(300).getEpochSecond(), // 5 minutes from now
                "iat",jweIssuedTime.getEpochSecond(),
                "key_context",keyContext));

        return CryptoUtil.generateJWE("platformsso-key-exchange-response+jwt",
                ECKey.parse(PlatformSSODeviceService.getInstance().getDeviceEncryptionKey(serialNumber)),
                partyVInfo,
                payload);


    }

    private JWEObject getServerEncryptedKeyContext(ECKey ecKey) throws JOSEException {
        Payload payload = new Payload(ecKey.toJSONObject());
        String serverSigningKeySecret = SystemConfiguration.getConfiguration(ServerUtils.PropertyConstants.PSSO_SERVER_KEY_PROTECTION_PASSWORD);
        return CryptoUtil.generateJWE("JOSE",serverSigningKeySecret,payload,16,100000);
    }

    private ECKey getDecryptedKeyContext(JWEObject jweObject) throws JOSEException, ParseException {
        String serverSigningKeySecret = SystemConfiguration.getConfiguration(ServerUtils.PropertyConstants.PSSO_SERVER_KEY_PROTECTION_PASSWORD);
        Payload payload = CryptoUtil.decryptJWE(serverSigningKeySecret,jweObject)
                .getPayload();
        return ECKey.parse(payload.toString());
    }
}
