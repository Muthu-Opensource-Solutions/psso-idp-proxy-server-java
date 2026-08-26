package com.muthuopensource.jakarta.resources;

import com.muthuopensource.jakarta.annotations.Authentication;
import com.muthuopensource.service.PlatformSSOKeyService;
import com.muthuopensource.utils.AuthenitcationType;
import com.muthuopensource.utils.PSSOUtils;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.util.Base64URL;
import jakarta.ws.rs.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Jakarta Resource Created to handle PSSO 2.0 Keyservice related API
 */
@Path(PSSOUtils.PSSOEndpointURLS.KEY_ENDPOINT_PATH)
@Authentication(AuthenitcationType.PSSO_AUTH)
public class PlatformSSOKeyResource {

    private static Logger logger = LoggerFactory.getLogger(PlatformSSOKeyResource.class);
    /**
     * Jakarta subresource representing Key Endpoint URL which handles Key Request, Key Exchange Request
     *
     * <a href="https://developer.apple.com/documentation/authenticationservices/supporting-key-requests-and-key-exchange-requests">API Documentation</a>
     * @param assertion
     * @return
     * @throws Exception
     */
    @POST
    @Produces("application/platformsso-key-response+jwt")
    public String handleRequest(@FormParam("assertion") String assertion) throws Exception {
        logger.info("PlatformSSOKeyResource : Received Key Request");
        logger.atDebug().log("PlatformSSOKeyResource : Assertion Received for Key Request : {}",assertion);
        JWSObject jws = JWSObject.parse(assertion);
        Map<String,Object> jwsPayloadMap = jws.getPayload().toJSONObject();
        String requestType = jwsPayloadMap.get("request_type").toString();
        String serialNumber = jwsPayloadMap.get("client_id").toString();
        String keyPurpose = jwsPayloadMap.get("key_purpose").toString();
        String userName = jwsPayloadMap.get("username").toString();
        String partyVInfo = ((Map<String,Object>) jwsPayloadMap.get("jwe_crypto")).get("apv").toString();
        logger.info("PlatformSSOKeyResource : Received Key Request, SN : {}, Key Purpose : {}",serialNumber,keyPurpose);
        if(requestType.equals("key_request")) {
            return PlatformSSOKeyService.getInstance()
                    .performPSSOKeyRequest(serialNumber, new Base64URL(partyVInfo), keyPurpose, userName)
                    .serialize();
        } else if (requestType.equals("key_exchange")) {
            String otherPublickey = jwsPayloadMap.get("other_publickey").toString();
            String keyContext = jwsPayloadMap.get("key_context").toString();
            return PlatformSSOKeyService.getInstance()
                    .performPSSOKeyExchange(serialNumber,new Base64URL(otherPublickey), new Base64URL(partyVInfo), keyContext)
                    .serialize();
        }

        throw new ForbiddenException("No valid request type found in the assertion. Expected 'key_request' or 'key_exchange', but found: " + requestType);
    }
}
