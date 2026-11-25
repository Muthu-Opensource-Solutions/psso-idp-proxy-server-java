package com.muthuopensource.jakarta.resources;


import com.muthuopensource.exceptions.OauthException;
import com.muthuopensource.jakarta.annotations.Authentication;
import com.muthuopensource.service.OIDCService;
import com.muthuopensource.utils.AuthenitcationType;
import com.muthuopensource.utils.PSSOUtils;
import com.muthuopensource.utils.ServerUtils;
import com.muthuopensource.utils.SystemConfiguration;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/**
 * Jakarta Resource Create to handle OIDC Related API Endpoints with PSSO-PROXY-IDP-SERVER
 */
@Path(PSSOUtils.OIDCEndpointURLs.OIDC)
public class OIDCResource {

    @Context
    private UriInfo uriInfo;

    private static Logger logger = LoggerFactory.getLogger(OIDCResource.class);

    /**
     * This Jakarta Sub-Resource is meant for Oauth Callback which the iDP eventually redirected as a result of User Registration
     * @param code
     * @return
     */
    @GET
    @Path(PSSOUtils.OIDCEndpointURLs.USER_REGISTRATION_CALLBACK_PATH)
    @Produces(MediaType.TEXT_HTML)
    @Authentication(AuthenitcationType.REGISTRATION_OIDC_STATE_AUTH)
    public Response handleUserRegistrationOIDCCallback(@QueryParam("code") String code){
        try {
            logger.info("OIDCResource : Recieved OIDC User Registration Callback code : {},",code);
            URI oidcRedirectURI = UriBuilder.newInstance()
                    .scheme(uriInfo.getRequestUri().getScheme())
                    .host(uriInfo.getRequestUri().getHost())
                    .path(uriInfo.getPath())
                    .build();
            UserInfo userInfo = OIDCService.getInstance().getOIDCAuthCodeGrantUserInfoResponse(code,oidcRedirectURI);
            logger.atDebug().log("OIDCResource : User Info Response for OIDC User Registration Callback : {}",userInfo.toJWTClaimsSet().toString());
            String base64encodedUserInfoClaims = Base64.getEncoder().encodeToString(userInfo.toJWTClaimsSet().toString().getBytes(StandardCharsets.UTF_8));

            return Response.ok()
                    .entity(PSSOUtils.getHTMLBasedWebPageRedirectXML("psso-client-oidc-callback://result=" + base64encodedUserInfoClaims))
                    .build();

        } catch (Exception e){
            logger.error("OIDCResource : Exception Occured during handleUserRegistrationOIDCCallback",e);
            throw new OauthException("Exception Occured during handleUserRegistrationOIDCCallback");
        }
    }

    /**
     * This Jakarta Sub-Resource is meant for User Registration OIDC Discovery which helps in Constructing OIDC Provider's
     * Authorization endpoint for initiating Auth Call with iDP
     * @return
     * @throws GeneralException
     * @throws IOException
     */
    @GET
    @Path(PSSOUtils.OIDCEndpointURLs.USER_REGISTRATION_DISCOVERY_PATH)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUserRegistrationDiscoveryResponse(){
        try{
            logger.info("OIDCResource : Received Request for User Registration Discovery");
            String host = uriInfo.getRequestUri().getHost();
            String callBackPath = String.join("/",
                    "",
                    PSSOUtils.OIDCEndpointURLs.OIDC,
                    PSSOUtils.OIDCEndpointURLs.USER_REGISTRATION_CALLBACK_PATH);

            //generating state param
            String state = PSSOUtils.generateRandomState();

            URI temporaryRedirectURI = OIDCService.getInstance().generateOIDCAuthCodeGrantAuthEndpointURI(callBackPath,host,state);
            logger.atDebug().log("OIDCResource : Temporary URI Redirect for User Registration : {}",temporaryRedirectURI.toString());
            return Response.temporaryRedirect(temporaryRedirectURI)
                    .cookie(PSSOUtils.createStateCookie(state))
                    .build();
        } catch (Exception e){
            logger.error("OIDCResource : Exception Occured during getUserRegistrationDiscoveryResponse",e);
            throw new OauthException("Exception Occured during getUserRegistrationDiscoveryResponse");
        }
    }
    /**
     * This Jakarta Sub-Resource handles macOS WebAuth Authorization request, substitutes the scheme, host, path
     * with upstream IdP's Authorization Server, sets redirect_uri to proxy callback endpoint, and redirects with State cookie.
     * @param state
     * @param loginHint
     * @return
     */
    @GET
    @Path(PSSOUtils.OIDCEndpointURLs.PSSO_OPENID_TYPE_AUTHORIZE_PATH)
    public Response handlePSSOWebAuthAuthorize(@QueryParam("state") String state,
                                              @QueryParam("login_hint") String loginHint) {
        try {
            logger.info("OIDCResource : Received Request for PSSO WebAuth Authorize");

            URI callbackURI = PSSOUtils.getPSSOWebAuthCallbackURI(uriInfo);

            OIDCProviderMetadata metaData = OIDCService.getInstance().getMetaData(GrantType.AUTHORIZATION_CODE);
            URI idpAuthEndpointURI = UriBuilder.fromUri(metaData.getAuthorizationEndpointURI())
                    .queryParam("response_type", "code")
                    .queryParam("client_id", SystemConfiguration.getConfiguration(ServerUtils.PropertyConstants.PSSO_AUTH_CODE_GRANT_OIDC_CLIENT_ID))
                    .queryParam("redirect_uri", callbackURI.toString())
                    .queryParam("scope", OIDCService.getInstance().getOIDCCummulativeScope())
                    .queryParam("state", state)
                    .queryParam("login_hint",loginHint)
                    .build();

            logger.debug("OIDCResource : Redirecting PSSO WebAuth Authorize to IdP: {}", idpAuthEndpointURI);

            return Response.status(302)
                    .location(idpAuthEndpointURI)
                    .cookie(PSSOUtils.createStateCookie(state))
                    .build();
        } catch (Exception e) {
            logger.error("OIDCResource : Exception Occurred during handlePSSOWebAuthAuthorize", e);
            throw new OauthException("Exception Occurred during handlePSSOWebAuthAuthorize");
        }
    }

    /**
     * This Jakarta Sub-Resource receives the redirect from upstream IdP, validates state against cookie,
     * and substitutes the redirect URI to com.apple.PlatformSSO://callback for macOS to dismiss the webview and start LoginRequest.
     * @param code
     * @param state
     * @return
     */
    @GET
    @Path(PSSOUtils.OIDCEndpointURLs.PSSO_OPENID_TYPE_CALLBACK_PATH)
    @Authentication(AuthenitcationType.REGISTRATION_OIDC_STATE_AUTH)
    @Produces(MediaType.TEXT_HTML)
    public Response handlePSSOWebAuthCallback(@QueryParam("code") String code,
                                             @QueryParam("state") String state) {
        try {
            URI pssoClientRedirectURI = URI.create("com.apple.PlatformSSO://callback?code=" + code + "&state=" + state);
            logger.debug("OIDCResource : Redirecting PSSO WebAuth Callback to client : {}", pssoClientRedirectURI);
            return Response.ok()
                    .entity(PSSOUtils.getHTMLBasedWebPageRedirectXML(pssoClientRedirectURI.toString()))
                    .build();
        } catch (Exception e) {
            logger.error("OIDCResource : Exception Occurred during handlePSSOWebAuthCallback", e);
            throw new OauthException("Exception Occurred during handlePSSOWebAuthCallback");
        }
    }

}
