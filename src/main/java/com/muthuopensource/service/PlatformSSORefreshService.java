package com.muthuopensource.service;

import com.muthuopensource.utils.OIDCUtils;
import com.muthuopensource.utils.PSSOUtils;
import com.muthuopensource.utils.ServerUtils;
import com.muthuopensource.utils.SystemConfiguration;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;

import java.net.URI;

public class PlatformSSORefreshService {
    private static PlatformSSORefreshService instance = null;

    public static PlatformSSORefreshService getInstance(){
        if (instance==null){
            instance = new PlatformSSORefreshService();
        }
        return instance;
    }

    private PlatformSSORefreshService(){}

    public JWEObject performPSSORefreshRequest(String refreshToken, String serialNumber,
                                               PSSOUtils.PSSOGrantTypes pssoType, Base64URL partyVInfo, String nonce) throws Exception {
        GrantType oauthGrantType = pssoType == PSSOUtils.PSSOGrantTypes.PASSWORD ? GrantType.PASSWORD : GrantType.AUTHORIZATION_CODE;
        URI tokenEndpointURI = OIDCService.getInstance().getMetaData(oauthGrantType).getTokenEndpointURI();

        String clientId = SystemConfiguration.getConfiguration(
                oauthGrantType==GrantType.PASSWORD ?
                        ServerUtils.PropertyConstants.PSSO_ROPG_CLIENT_ID :
                        ServerUtils.PropertyConstants.PSSO_AUTH_CODE_GRANT_OIDC_CLIENT_ID);
        String clientSecret = SystemConfiguration.getConfiguration(
                oauthGrantType==GrantType.PASSWORD ?
                        ServerUtils.PropertyConstants.PSSO_ROPG_CLIENT_SECRET :
                        ServerUtils.PropertyConstants.PSSO_AUTH_CODE_GRANT_OIDC_CLIENT_SECRET);

        OIDCTokenResponse tokenResponse = OIDCUtils.performTokenRequest(tokenEndpointURI,refreshToken,clientId,clientSecret);

        return PlatformSSOLoginService.getInstance().generatePSSOLoginResponse(tokenResponse.getOIDCTokens().getAccessToken().toString(),
                tokenResponse.getOIDCTokens().getRefreshToken().toString(),
                serialNumber, partyVInfo, nonce, oauthGrantType);
    }
}
