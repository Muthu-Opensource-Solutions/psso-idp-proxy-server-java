package com.muthuopensource.jakarta.resources;

import com.muthuopensource.jakarta.annotations.Authentication;
import com.muthuopensource.service.PlatformSSORefreshService;
import com.muthuopensource.utils.AuthenitcationType;
import com.muthuopensource.utils.PSSOUtils;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.util.Base64URL;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Jakarta Resource created to handle PSSO Refresh Request
 */
@Path(PSSOUtils.PSSOEndpointURLS.REFRESH_ENDPOINT_PATH)
@Authentication(AuthenitcationType.PSSO_AUTH)
public class PlatformSSORefreshResource {

    private static Logger logger = LoggerFactory.getLogger(PlatformSSORefreshResource.class);

    /**
     * Jakarta Resource created to handle PSSO Refresh Request <a href="https://developer.apple.com/documentation/authenticationservices/asauthorizationproviderextensionloginconfiguration/refreshendpointurl">API Documentation</a>
     */
    @POST
    @Produces("application/platformsso-login-response+jwt")
    public String handleRequest(@FormParam("assertion") String assertion) throws Exception {
        logger.info("Received Refresh Request : Assertion : {}",assertion);
        JWSObject jws = JWSObject.parse(assertion);
        Map<String,Object> jwsPayloadMap = jws.getPayload().toJSONObject();
        String partyVInfo = ((Map<String,Object>) jwsPayloadMap.get("jwe_crypto")).get("apv").toString();
        String serialNumber = jwsPayloadMap.get("client_id").toString();
        String nonce = jwsPayloadMap.get("nonce").toString();
        String refreshToken = jwsPayloadMap.get("refresh_token").toString();
        String pssoTypeString = jwsPayloadMap.get("psso_type").toString();
        PSSOUtils.PSSOGrantTypes pssoGrantType = PSSOUtils.PSSOGrantTypes.valueOf(pssoTypeString);

        return PlatformSSORefreshService.getInstance()
                .performPSSORefreshRequest(refreshToken,serialNumber,pssoGrantType, new Base64URL(partyVInfo),nonce)
                .serialize();
    }
}
