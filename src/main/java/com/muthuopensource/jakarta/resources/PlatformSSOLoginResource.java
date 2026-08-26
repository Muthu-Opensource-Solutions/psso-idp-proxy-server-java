package com.muthuopensource.jakarta.resources;

import com.muthuopensource.jakarta.annotations.Authentication;
import com.muthuopensource.exceptions.OauthException;
import com.muthuopensource.service.PlatformSSOLoginService;
import com.muthuopensource.utils.AuthenitcationType;
import com.muthuopensource.utils.PSSOUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.GeneralException;
import jakarta.ws.rs.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
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
            logger.atDebug().log("PlatformSSOLoginResource : Assertion Received for Login Request: {}",assertion);
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
        } catch (OauthException e){
            throw e;
        } catch (Exception e){
            throw new OauthException("Failed to process login request. Error: " + e.getMessage());
        }
    }
}
