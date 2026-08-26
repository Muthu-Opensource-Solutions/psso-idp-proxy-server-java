package com.muthuopensource.jakarta.resources;


import com.muthuopensource.exceptions.OauthException;
import com.muthuopensource.jakarta.annotations.Authentication;
import com.muthuopensource.service.OIDCService;
import com.muthuopensource.utils.AuthenitcationType;
import com.muthuopensource.utils.PSSOUtils;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

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
    @Produces(MediaType.APPLICATION_JSON)
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
            return Response.status(302)
                    .location(new URI("psso-client-oidc-callback://result=" + base64encodedUserInfoClaims))
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
            byte[] nonceBytes = new byte[16];
            new SecureRandom().nextBytes(nonceBytes);
            String state = Base64.getEncoder().encodeToString(nonceBytes);

            URI temporaryRedirectURI = OIDCService.getInstance().generateOIDCAuthCodeGrantAuthEndpointURI(callBackPath,host,state);
            logger.atDebug().log("OIDCResource : Temporary URI Redirect for User Registration : {}",temporaryRedirectURI.toString());
            return Response.temporaryRedirect(temporaryRedirectURI)
                    .cookie(new NewCookie("X-State-Cookie",state))
                    .build();
        } catch (Exception e){
            logger.error("OIDCResource : Exception Occured during getUserRegistrationDiscoveryResponse",e);
            throw new OauthException("Exception Occured during getUserRegistrationDiscoveryResponse");
        }
    }
}
