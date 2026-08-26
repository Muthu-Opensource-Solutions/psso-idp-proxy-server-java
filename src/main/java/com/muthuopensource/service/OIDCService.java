package com.muthuopensource.service;

import com.muthuopensource.utils.OIDCUtils;
import com.muthuopensource.utils.ServerUtils;
import com.muthuopensource.utils.SystemConfiguration;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import jakarta.ws.rs.core.UriBuilder;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
public class OIDCService {

    private static OIDCService instance = null;

    public static final OIDCService getInstance(){
        if(instance==null){
            instance = new OIDCService();
        }
        return instance;
    }

    public OIDCProviderMetadata getMetaData(GrantType grantType) throws GeneralException, IOException {
        if(grantType.equals(GrantType.PASSWORD)){
            if(OIDCMetaData.passwordGrantMetaData ==null){
                OIDCMetaData.syncOIDCMetaData();
            }
            return OIDCMetaData.passwordGrantMetaData;
        } else if (grantType.equals(GrantType.AUTHORIZATION_CODE)) {
            if(OIDCMetaData.authCodeGrantMetaData == null){
                OIDCMetaData.syncOIDCMetaData();
            }
            return OIDCMetaData.authCodeGrantMetaData;
        }
        return null;
    }

    /**
     * Class Responsible for Storing OIDCMetada for ROPG Enabled OpenID Provider, Authorization Grant Flow Enabled OpenID Provider
     */
    public class OIDCMetaData{
        //OIDC Server used to validate username,password hence this can be called as ROPG Enabled OpenID Provider
        private static OIDCProviderMetadata passwordGrantMetaData = null;
        //OIDC Server used to validate user with OIDC Protocol this can be called as Authorization Grant Flow Enabled OpenID Provider
        private static OIDCProviderMetadata authCodeGrantMetaData = null;

        //Its Customer's wish to configure both flows in same instance (or) Use Separate Instances with tighter Authentication Policy

        public static void syncOIDCMetaData() throws GeneralException, IOException {
            try {
                Issuer passwordGrantIssuer = new Issuer(SystemConfiguration.getConfiguration(ServerUtils.PropertyConstants.PSSO_ROPG_OIDC_PROVIDER_URL));
                Issuer authCodeGrantIssuer = new Issuer(SystemConfiguration.getConfiguration(ServerUtils.PropertyConstants.PSSO_AUTH_CODE_GRANT_OIDC_PROVIDER_URL));
                passwordGrantMetaData =  OIDCProviderMetadata.resolve(passwordGrantIssuer);
                authCodeGrantMetaData = OIDCProviderMetadata.resolve(authCodeGrantIssuer);
            } catch (Exception e) {
                throw new GeneralException("Error while fetching OIDC metadata", e);
            }
        }

    }

    /**
     * Generates Authorization endpoint for authorization code grant flow using  Authorization Grant Flow Enabled OpenID Provider
     * @param path
     * @param serverHostName
     * @param state
     * @return
     * @throws GeneralException
     * @throws IOException
     */
    public URI generateOIDCAuthCodeGrantAuthEndpointURI(String path,String serverHostName,String state) throws GeneralException, IOException {
        OIDCProviderMetadata metaData = getMetaData(GrantType.AUTHORIZATION_CODE);
        URL redirectURL = UriBuilder.newInstance()
                .scheme("https")
                .host(serverHostName)
                .path(path)
                .build().toURL();
        return UriBuilder.fromUri( metaData.getAuthorizationEndpointURI())
                .queryParam("response_type","code")
                .queryParam("client_id",SystemConfiguration.getConfiguration(ServerUtils.PropertyConstants.PSSO_AUTH_CODE_GRANT_OIDC_CLIENT_ID))
                .queryParam("redirect_uri",redirectURL.toString())
                .queryParam("scope",getOIDCCummulativeScope())
                .queryParam("grant_type",GrantType.AUTHORIZATION_CODE.getValue())
                .queryParam("state",state) // Implement Oauth State Query Param Later
                .build();
    }

    public String getOIDCCummulativeScope(){
        String additionalCustomScope = SystemConfiguration.getConfigurationOrDefault("PSSO_OIDC_CUSTOM_SCOPES","");
        String mandatoryScope = String.join(" ","openid","profile","email");
        if(additionalCustomScope.isEmpty())
            return mandatoryScope;
        return String.join(" ",mandatoryScope, additionalCustomScope);
    }

    /**
     * Retrives Response of /userInfo using AccessTokens generated during Oauth Grant Flow, Exchanges code for AccessToken.
     * @param code
     * @param redirectURI
     * @return
     * @throws GeneralException
     * @throws IOException
     */
    public UserInfo getOIDCAuthCodeGrantUserInfoResponse(String code,URI redirectURI) throws GeneralException, IOException {
        OIDCProviderMetadata authCodeGrantMetaData = getInstance().getMetaData(GrantType.AUTHORIZATION_CODE);
        String authCodeGrantOIDCServerClientID = SystemConfiguration.getConfiguration(ServerUtils.PropertyConstants.PSSO_AUTH_CODE_GRANT_OIDC_CLIENT_ID);
        String authCodeGrantOIDCServerClientSecret = SystemConfiguration.getConfiguration(ServerUtils.PropertyConstants.PSSO_AUTH_CODE_GRANT_OIDC_CLIENT_SECRET);
        OIDCTokenResponse tokenResponse = OIDCUtils.performTokenRequest(authCodeGrantMetaData.getTokenEndpointURI(),code,
                authCodeGrantOIDCServerClientID,authCodeGrantOIDCServerClientSecret,
                redirectURI,getOIDCCummulativeScope());
        String accessToken = tokenResponse.getOIDCTokens().getAccessToken().toString();
        return OIDCUtils.performUserInfoRequest(authCodeGrantMetaData.getUserInfoEndpointURI(),accessToken);
    }
}