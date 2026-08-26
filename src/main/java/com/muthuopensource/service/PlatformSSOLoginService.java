package com.muthuopensource.service;

import com.muthuopensource.exceptions.OauthException;
import com.muthuopensource.utils.*;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

public class PlatformSSOLoginService {
    private static PlatformSSOLoginService instance = null;

    public static PlatformSSOLoginService getInstance(){
        if (instance==null){
            instance = new PlatformSSOLoginService();
        }
        return instance;
    }


    /**
     * As Per PSSO Login Request Protocol Username, Password are verified with the Identity Provider using OIDC
     * The JWE Response containing the requested id_token is created using Static deviceEncryptionKey and Server's Ephermal Key
     * @param userName
     * @param password
     * @param serialNumber
     * @param partyVInfo
     * @return
     * @throws OauthException
     * @throws IOException
     * @throws ParseException
     * @throws java.text.ParseException
     * @throws JOSEException
     */
    public JWEObject performPSSOLoginRequst(String userName, String password,
                                            String serialNumber, Base64URL partyVInfo,
                                            String nonce)
            throws Exception {
        URI tokenEndpointURI = OIDCService.getInstance().getMetaData(GrantType.PASSWORD).getTokenEndpointURI();
        OIDCTokenResponse tokenResponse = OIDCUtils.performTokenRequest(tokenEndpointURI, userName, password,
                SystemConfiguration.getConfiguration(ServerUtils.PropertyConstants.PSSO_ROPG_CLIENT_ID),
                SystemConfiguration.getConfiguration(ServerUtils.PropertyConstants.PSSO_ROPG_CLIENT_SECRET),
                OIDCService.getInstance().getOIDCCummulativeScope());

        return generatePSSOLoginResponse(tokenResponse.getOIDCTokens().getAccessToken().toString(),serialNumber,partyVInfo,nonce,GrantType.PASSWORD);
    }

    /**
     * Given AccessToken, SerialNumber and PartyVInfo, the JWE Response is generated as per PSSO Login Response Protocol
     * @param accessToken
     * @param serialNumber
     * @param partyVInfo
     * @return
     * @throws ParseException
     * @throws IOException
     * @throws java.text.ParseException
     * @throws JOSEException
     */
    private JWEObject generatePSSOLoginResponse(String accessToken,String serialNumber,Base64URL partyVInfo,String nonce,GrantType grantType)
            throws Exception {
        URI userInfoEndpointURI = OIDCService.getInstance().getMetaData(grantType).getUserInfoEndpointURI();
        UserInfo userInfo = OIDCUtils.performUserInfoRequest(userInfoEndpointURI, accessToken);


        JWTClaimsSet idTokenJwtClaimsSet = new JWTClaimsSet.Builder(userInfo.toJWTClaimsSet())
                .issuer("psso-idp-proxy-server-java")
                .audience(serialNumber)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusMillis(86400000)))// 1 Day expiry
                .claim("nonce",nonce)
                .build();


        Payload jwePayload = new Payload(Map.of("refresh_token","dummy",
                "expires_in",idTokenJwtClaimsSet.getExpirationTime().toInstant().toEpochMilli(),
                "id_token", CryptoUtil.generateSignedJWT(PSSOUtils.getServerSigningKey(), idTokenJwtClaimsSet).serialize(),
                "token_type","Bearer"));

        return CryptoUtil.generateJWE("platformsso-login-response+jwt",
                ECKey.parse(PlatformSSODeviceService.getInstance().getDeviceEncryptionKey(serialNumber)),
                partyVInfo,
                jwePayload);
    }
}
