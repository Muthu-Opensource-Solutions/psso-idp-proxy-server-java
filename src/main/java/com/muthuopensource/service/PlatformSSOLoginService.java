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
                                            String nonce) throws Exception {
        URI tokenEndpointURI = OIDCService.getInstance().getMetaData(GrantType.PASSWORD).getTokenEndpointURI();
        OIDCTokenResponse tokenResponse = OIDCUtils.performTokenRequest(tokenEndpointURI, userName, password,
                SystemConfiguration.getConfiguration(ServerUtils.PropertyConstants.PSSO_ROPG_CLIENT_ID),
                SystemConfiguration.getConfiguration(ServerUtils.PropertyConstants.PSSO_ROPG_CLIENT_SECRET),
                OIDCService.getInstance().getOIDCCummulativeScope());

        return generatePSSOLoginResponse(tokenResponse.getOIDCTokens().getAccessToken().toString(),
                tokenResponse.getOIDCTokens().getRefreshToken().toString(),
                serialNumber,partyVInfo,nonce,GrantType.PASSWORD);
    }

    /**
     * As Per PSSO Login Request Protocol code is Exchanged with the iDP to verify User using Oauth grant_Type=authorization_code
     * The JWE Response containing the requested id_token is created using Static deviceEncryptionKey and Server's Ephermal Key
     * @param redirectURI RedirectURI used in Oauth Authentication with authorization Server
     * @param code authorization_code returned by iDP to Callee
     * @param scope Scopes for which the Access Token is being requested
     * @param serialNumber SerialNumber of the Device
     * @param partyVInfo PartyVInfo for
     * @param nonce Nonce Sent by Device to be included in id Token
     * @return
     * @throws Exception
     */
    public JWEObject performPSSOLoginRequest(URI redirectURI, String code,
                                             String scope,String serialNumber,
                                             Base64URL partyVInfo,String nonce) throws Exception {
        URI tokenEndpointURI = OIDCService.getInstance().getMetaData(GrantType.AUTHORIZATION_CODE).getTokenEndpointURI();
        String authCodeGrantOIDCServerClientID = SystemConfiguration.getConfiguration(ServerUtils.PropertyConstants.PSSO_AUTH_CODE_GRANT_OIDC_CLIENT_ID);
        String authCodeGrantOIDCServerClientSecret = SystemConfiguration.getConfiguration(ServerUtils.PropertyConstants.PSSO_AUTH_CODE_GRANT_OIDC_CLIENT_SECRET);
        OIDCTokenResponse tokenResponse = OIDCUtils.performTokenRequest(tokenEndpointURI,code,
                authCodeGrantOIDCServerClientID,authCodeGrantOIDCServerClientSecret,
                redirectURI,scope);
        return generatePSSOLoginResponse(tokenResponse.getOIDCTokens().getAccessToken().toString(),
                tokenResponse.getOIDCTokens().getRefreshToken().toString(),
                serialNumber,partyVInfo,nonce,GrantType.AUTHORIZATION_CODE);
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
    public JWEObject generatePSSOLoginResponse(String accessToken,String refreshToken,String serialNumber,Base64URL partyVInfo,String nonce,GrantType grantType)
            throws Exception {
        URI userInfoEndpointURI = OIDCService.getInstance().getMetaData(grantType).getUserInfoEndpointURI();
        UserInfo userInfo = OIDCUtils.performUserInfoRequest(userInfoEndpointURI, accessToken);

        Date issuedTime = new Date();//
        Date expirationTime = new Date(issuedTime.getTime() + 60);//60seconds expiry


        JWTClaimsSet idTokenJwtClaimsSet = new JWTClaimsSet.Builder(userInfo.toJWTClaimsSet())
                .issuer("psso-idp-proxy-server-java")
                .audience(serialNumber)
                .issueTime(issuedTime)
                .expirationTime(expirationTime)
                .claim("nonce",nonce)
                .build();

        Payload jwePayload = new Payload(Map.of("refresh_token",refreshToken,
                "expires_in",3600*18,//Setting Expiration to 18hours as this is maximum LoginFrequency Allowed Time according to PSSO
                "id_token", CryptoUtil.generateSignedJWT(PSSOUtils.getServerSigningKey(), idTokenJwtClaimsSet).serialize(),
                "token_type","Bearer"));

        return CryptoUtil.generateJWE("platformsso-login-response+jwt",
                ECKey.parse(PlatformSSODeviceService.getInstance().getDeviceEncryptionKey(serialNumber)),
                partyVInfo,
                jwePayload);
    }
}
