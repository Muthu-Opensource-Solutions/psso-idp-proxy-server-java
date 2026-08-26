package com.muthuopensource.utils;


import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.crypto.impl.AESGCM;
import com.nimbusds.jose.crypto.impl.AuthenticatedCipherText;
import com.nimbusds.jose.crypto.impl.ConcatKDF;
import com.nimbusds.jose.crypto.impl.ECDH;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.Container;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

public class CryptoUtil {

    /**
     * Generates an JWE using ECDH-ES algorithm
     * @param receipientPublicKey
     * @param partyVInfo
     * @param payload Plain text payload to be encrypted
     * @return EncryptedJWT
     * @throws JOSEException
     */
    public static JWEObject generateJWE(String typ, ECKey receipientPublicKey, Base64URL partyVInfo, Payload payload) throws Exception {
        // 1. Generate an Ephemeral Key Pair (must be P-256 for Apple)
        ECKey ephemeralKey = new ECKeyGenerator(Curve.P_256).generate();

        // Buffer total size = 4 (prefix len) + 5 ("APPLE") + 4 (EPK len) + 1 (0x04) + 32 (X) + 32 (Y) = 78 bytes
        ByteBuffer apuBuffer = ByteBuffer.allocate(78);
        apuBuffer.putInt(5);                                    // Length of "APPLE" (4 bytes)
        apuBuffer.put("APPLE".getBytes(StandardCharsets.UTF_8));// Prefix Data (5 bytes)
        apuBuffer.putInt(65);                                   // Length of uncompressed EPK (4 bytes)
        apuBuffer.put((byte) 0x04);                             // Uncompressed point indicator (1 byte)
        apuBuffer.put(ephemeralKey.getX().decode());                                       // X coordinate (32 bytes)
        apuBuffer.put(ephemeralKey.getY().decode());                                       // Y coordinate (32 bytes)

        Base64URL partyUInfo = Base64URL.encode(apuBuffer.array());

        // 2. Create the JWE Header
        // Note: We MUST include the ephemeralPublicKey in the header as well
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                .type(new JOSEObjectType(typ))
                .agreementPartyUInfo(partyUInfo)
                .agreementPartyVInfo(partyVInfo)
                .ephemeralPublicKey(ephemeralKey.toPublicJWK())
                .build();

        // 3. Perform ECDH to get the Shared Secret (Z)
        KeyAgreement ecdh = KeyAgreement.getInstance("ECDH");
        ecdh.init(ephemeralKey.toECPrivateKey());
        ecdh.doPhase(receipientPublicKey.toECPublicKey(), true);
        byte[] Z = ecdh.generateSecret();
        SecretKey ZKey = new SecretKeySpec(Z, "ECDH");

        // 4. Derive the Content Encryption Key (CEK) using Nimbus's internal ConcatKDF
        ConcatKDF kdf = new ConcatKDF("SHA-256");
        SecretKey cek = ECDH.deriveSharedKey(header, ZKey, kdf);

        // 5. Encrypt the Payload manually using AES-GCM
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        AuthenticatedCipherText authCipherText = AESGCM.encrypt(
                cek,
                new Container<>(iv),
                payload.toBytes(),
                header.toBase64URL().toString().getBytes(StandardCharsets.US_ASCII),
                null
        );

        // 6. Assemble the final JWE Object
        // JWEObject allows you to instantiate it directly using the encoded Base64URL parts
        return new JWEObject(
                header.toBase64URL(),
                null, // encryptedKey is empty/null for direct ECDH-ES
                Base64URL.encode(iv),
                Base64URL.encode(authCipherText.getCipherText()),
                Base64URL.encode(authCipherText.getAuthenticationTag())
        );
    }

    /**
     * Generates an JWE using PBES2_HS512_A256KW algorithm and A256GCM encryption method.
     * @param sharedSecret
     * @param payload
     * @param saltLength
     * @param iterationCount
     * @return
     * @throws JOSEException
     */
    public static JWEObject generateJWE(String typ,String sharedSecret, Payload payload,int saltLength,int iterationCount) throws JOSEException {
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.PBES2_HS512_A256KW, EncryptionMethod.A256GCM)
                .type(new JOSEObjectType(typ))
                .build();

        JWEObject jweObject = new JWEObject(header,payload);
        jweObject.encrypt(new PasswordBasedEncrypter(sharedSecret,saltLength,iterationCount));
        return jweObject;
    }

    /**
     * Decrypts and get JWE Payload using PBES2_HS512_A256KW Algo
     * @param sharedSecret
     * @param jweObject
     * @return
     * @throws JOSEException
     */
    public static JWEObject decryptJWE(String sharedSecret, JWEObject jweObject) throws JOSEException {
        jweObject.decrypt(new PasswordBasedDecrypter(sharedSecret));
        return jweObject;
    }

    /**
     * Generates a signed JWT using ES256 algorithm.
     * @param signingKey
     * @param claims
     * @return SignedJWT
     * @throws JOSEException
     */
    public static SignedJWT generateSignedJWT(ECKey signingKey, JWTClaimsSet claims) throws JOSEException {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(signingKey.getKeyID())
                .type(JOSEObjectType.JWT)
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claims);
        signedJWT.sign(new ECDSASigner(signingKey));

        return signedJWT;
    }

    /**
     * Generate EC Key pair with mentioned Curve
     * @param curve
     * @return
     * @throws Exception
     */
    public static KeyPair generateECKeyPair(String curve) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curve);
        keyPairGenerator.initialize(ecSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public static X509Certificate generateSelfSignedCertificate(String serialNumber,KeyPair keyPair) throws Exception {
        // 2. Define Names and Serial Number
        X500Name dnName = new X500Name("CN=" + serialNumber + ", O=com.muthuopensource.psso-idp-proxy-server-java");
        BigInteger sn = BigInteger.valueOf(System.currentTimeMillis());

        // 3. Set Validity Dates (1 Year validity)
        Instant now = Instant.now();
        Date notBefore = Date.from(now);
        Date notAfter = Date.from(now.plus(365, ChronoUnit.DAYS));

        // 4. Initialize structural builder
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName,                // Issuer
                sn,          // Serial Number
                notBefore,             // Start Date
                notAfter,              // End Date
                dnName,                // Subject
                keyPair.getPublic()    // Subject Public Key (EC Public Key)
        );

        // 5. Use ECDSA for signing
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .build(keyPair.getPrivate());

        // 6. Convert to standard Java X509Certificate
        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter()
                .getCertificate(certHolder);
    }
}
