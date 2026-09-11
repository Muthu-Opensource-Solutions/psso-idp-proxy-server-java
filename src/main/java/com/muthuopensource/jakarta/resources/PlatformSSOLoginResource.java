package com.muthuopensource.jakarta.resources;

import com.muthuopensource.jakarta.annotations.Authentication;
import com.muthuopensource.exceptions.OauthException;
import com.muthuopensource.service.PlatformSSOLoginService;
import com.muthuopensource.utils.AlgoUtils;
import com.muthuopensource.utils.AuthenitcationType;
import com.muthuopensource.utils.PSSOUtils;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.util.Base64URL;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MultivaluedMap;

import jakarta.ws.rs.core.UriBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.Map;

/**
 * Jakarta Resource created to handle PSSO Login Request
 */
@Path(PSSOUtils.PSSOEndpointURLS.TOKEN_ENDPOINT_PATH)
@Authentication(AuthenitcationType.PSSO_AUTH)
public class PlatformSSOLoginResource {


    private static Logger logger = LoggerFactory.getLogger(PlatformSSOLoginResource.class);
    /**
     * Jakarta Resource created to handle PSSO Login Request <a href="https://developer.apple.com/documentation/authenticationservices/creating-and-validating-a-login-request">API Documentation</a>
     */
    @POST
    @Produces("application/platformsso-login-response+jwt")
    public String handleRequest(@FormParam("assertion") String assertion) throws OauthException {
        try{
            logger.info("PlatformSSOLoginResource : Received Login Request");
            JWSObject jws = JWSObject.parse(assertion);
            Map<String,Object> jwsPayloadMap = jws.getPayload().toJSONObject();
            String grantType = jwsPayloadMap.get("grant_type").toString();
            logger.atDebug().log("PlatformSSOLoginResource : Assertion Received for Login Request: {}, GrantType : {}",assertion,grantType);
            logger.info("PlatformSSOLoginResource : Received Login Request for Grant Type {}",grantType);
            if(PSSOUtils.PSSOGrantTypes.PASSWORD.equals(grantType)){
                return handleGrantTypePassword(assertion);
            } else if (PSSOUtils.PSSOGrantTypes.OPENID.equals(grantType)) {
                return handleGrantTypeTokenExchange(assertion);
            }
            throw new OauthException("Invalid Login GrantType Received");
        } catch (OauthException e){
            throw e;
        } catch (Exception e){
            throw new OauthException("Failed to process login request. Error: " + e.getMessage());
        }
    }

    /**
     * Handles PSSO Login Request For GrantType : Password
     * @param assertion Login Request JWT Assertion Sent by macOS
     * @return
     * @throws Exception
     */
    private String handleGrantTypePassword(String assertion) throws Exception {
        JWSObject jws = JWSObject.parse(assertion);
        Map<String,Object> jwsPayloadMap = jws.getPayload().toJSONObject();
        String userName = jwsPayloadMap.get("username").toString();
        String password = jwsPayloadMap.get("password").toString();
        String partyVInfo = ((Map<String,Object>) jwsPayloadMap.get("jwe_crypto")).get("apv").toString();
        String serialNumber = jwsPayloadMap.get("client_id").toString();
        String nonce = jwsPayloadMap.get("nonce").toString();
        return PlatformSSOLoginService.getInstance()
                .performPSSOLoginRequst(userName,password,serialNumber,new Base64URL(partyVInfo),nonce)
                .serialize();
    }

    /**
     * Handles PSSO Login Request For GrantType : urn:ietf:params:oauth:grant-type:token-exchange ( OpenID )
     * @param assertion Login Request JWT Assertion Sent by macOS
     * @return
     * @throws Exception
     */
    private String handleGrantTypeTokenExchange(String assertion) throws Exception {
        JWSObject jws = JWSObject.parse(assertion);
        Map<String,Object> jwsPayloadMap = jws.getPayload().toJSONObject();
        String subjectToken = jwsPayloadMap.get("subject_token").toString();
        String partyVInfo = ((Map<String,Object>) jwsPayloadMap.get("jwe_crypto")).get("apv").toString();
        String serialNumber = jwsPayloadMap.get("client_id").toString();
        String nonce = jwsPayloadMap.get("nonce").toString();
        String scope = jwsPayloadMap.get("scope").toString();

        URI oidcRedirectURI = URI.create(subjectToken);
        MultivaluedMap<String,String> queryParams = AlgoUtils.decodeQueryParam(oidcRedirectURI.getQuery());
        String code = queryParams.getFirst("code");

        URI redirectURIWithourQuery = UriBuilder.newInstance()
                .scheme(oidcRedirectURI.getScheme())
                .host(oidcRedirectURI.getHost())
                .path(oidcRedirectURI.getPath())
                .build();
        return PlatformSSOLoginService.getInstance()
                .performPSSOLoginRequest(redirectURIWithourQuery,code,scope,serialNumber,new Base64URL(partyVInfo),nonce)
                .serialize();
    }
}
