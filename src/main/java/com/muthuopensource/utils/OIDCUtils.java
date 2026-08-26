package com.muthuopensource.utils;

import com.muthuopensource.exceptions.OauthException;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;

public class OIDCUtils {
    private static Logger logger = LoggerFactory.getLogger(OIDCUtils.class);
    /**
     * Perform an OAuth token request for Resource Owner Password Grant Workflow ( ROPG )
     * @param tokenEndpointURI
     * @param userName
     * @param password
     * @param clientID
     * @param clientSecret
     * @param scopeString
     * @return OIDCTokenResponse
     * @throws ParseException
     * @throws IOException
     */
    public static OIDCTokenResponse performTokenRequest(URI tokenEndpointURI, String userName,
                                                 String password, String clientID,
                                                 String clientSecret, String scopeString) throws IOException, ParseException, OauthException {
        AuthorizationGrant grant = new ResourceOwnerPasswordCredentialsGrant(userName,new Secret(password));
        ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID(clientID), new Secret(clientSecret));
        Scope scope = new Scope(scopeString);
        TokenResponse tokenResponse = OIDCTokenResponseParser.parse(new TokenRequest(tokenEndpointURI, clientAuth, grant, scope)
                .toHTTPRequest().send());
        if (tokenResponse.indicatesSuccess())
            return (OIDCTokenResponse) tokenResponse.toSuccessResponse();

        TokenErrorResponse tokenErrorResponse = (TokenErrorResponse) tokenResponse;

        logger.error("Error Occurred During Token Request , Token Response Body : {}",tokenErrorResponse.toJSONObject().toJSONString());
        throw new OauthException("Error Occurred During Token Request, Token Response Body :" + tokenErrorResponse.toJSONObject().toJSONString());
    }

    /**
     * Perform an OAuth token request for Authorization Code Grant Flow
     * @param tokenEndpointURI
     * @param code
     * @param clientID
     * @param clientSecret
     * @param redirectURI
     * @return
     */
    public static OIDCTokenResponse performTokenRequest(URI tokenEndpointURI, String code, String clientID, String clientSecret, URI redirectURI,String scope) throws IOException, ParseException {
        ClientAuthentication clientAuthentication = new ClientSecretPost(new ClientID(clientID),new Secret(clientSecret));
        AuthorizationGrant grant = new AuthorizationCodeGrant(new AuthorizationCode(code),redirectURI);
        TokenRequest tokenRequest = new TokenRequest(tokenEndpointURI,clientAuthentication,grant, Scope.parse(scope));
        TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest()
                .send());
        if (tokenResponse.indicatesSuccess())
            return (OIDCTokenResponse) tokenResponse.toSuccessResponse();

        TokenErrorResponse tokenErrorResponse = (TokenErrorResponse) tokenResponse;

        logger.error("Error Occurred During Token Request , Token Response Body : {}",tokenErrorResponse.toJSONObject().toJSONString());
        throw new OauthException("Error Occurred During Token Request, Token Response Body :" + tokenErrorResponse.toJSONObject().toJSONString());
    }

    /**
     * Perform a UserInfo request using the provided access token
     * @param userInfoEndpointURI
     * @param accessToken
     * @return
     * @throws ParseException
     * @throws IOException
     */
    public static UserInfo performUserInfoRequest(URI userInfoEndpointURI,String accessToken) throws ParseException, IOException, OauthException {
        HTTPResponse res = new UserInfoRequest(userInfoEndpointURI, new BearerAccessToken(accessToken))
                .toHTTPRequest().send();
        UserInfoResponse userInfoResponse = UserInfoResponse.parse(res);
        if (userInfoResponse.indicatesSuccess())
            return userInfoResponse.toSuccessResponse().getUserInfo();

        UserInfoErrorResponse errorResponse = userInfoResponse.toErrorResponse();

        logger.error("Error Occurred During UserInfo Request , UserInfo Response Body : {}",errorResponse.getErrorObject().toJSONObject().toJSONString());
        throw new OauthException("Error Occurred During Token Request, Token Response Body :" + errorResponse.getErrorObject().toJSONObject().toJSONString());
    }
}
