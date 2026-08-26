package com.muthuopensource.jakarta.filters.authenticationfilterutil;

import com.muthuopensource.service.PlatformSSODeviceService;
import com.muthuopensource.service.PlatformSSONonceService;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;


/**
 * ServerAuthentication Implementation meant for PSSO assertion JWT Authentication for Key Service, Login Request, Nonce Request etc.,
 * <a href="https://developer.apple.com/documentation/authenticationservices/authentication-process">Platform SSO Technology</a> can be referred to know on areas where Signature Verification is needed
 */
class PSSOAuthentication implements ServerAuthenticaiton{

    private Logger logger = LoggerFactory.getLogger(PSSOAuthentication.class);
    /**
     * Checks if the JWT is Cryptographically signed by EC-256 deviceSigningKey which is exchanged in Device Registraiton Phase
     * @param containerRequestContext
     * @return true / false
     */
    @Override
    public boolean authenticate(ContainerRequestContext containerRequestContext) {
        try{
            byte[] body = containerRequestContext.getEntityStream().readAllBytes();
            containerRequestContext.setEntityStream(new ByteArrayInputStream(body));
            String bodyStr = new String(body);
            MultivaluedMap<String,String> paramsMap = decodeQueryParam(bodyStr);

            String assertion = paramsMap.getFirst("assertion");
            logger.atDebug().log("PSSOAuthentication : Assertion Received {}",assertion);
            JWSObject jwsObject = JWSObject.parse(assertion);
            Map<String,Object> payloadMap = jwsObject.getPayload().toJSONObject();
            String clientId = payloadMap.get("client_id").toString();
            ECKey deviceSigningKey = ECKey.parse(PlatformSSODeviceService.getInstance().getDeviceSigningKey(clientId));

            if(!jwsObject.getHeader().getKeyID().equals(deviceSigningKey.getKeyID())){
                logger.info("PSSOAuthentication : Key ID mismatch:- JWT kid : {}  DeviceSigning kid : {}",jwsObject.getHeader().getKeyID(),deviceSigningKey.getKeyID());
                logger.info("PSSOAuthentication : Its Recommended to associate the MDM Platform SSO Profile to the device again to get the latest signing key {}",clientId);
                return false;
            }

            String nonce = payloadMap.get("request_nonce").toString();
            if(!PlatformSSONonceService.getInstance().verifyNonceAndDelete(nonce,clientId)){
                logger.info("PSSOAuthentication : Nonce Replay Attack was being Attempted for the Device SN: {}", clientId);
                return false;
            }

            return jwsObject.verify(new ECDSAVerifier(deviceSigningKey));
        } catch (Exception e){
            logger.error("PSSOAuthentication : Error while authenticating the request: ",e);
        }
        return false;
    }

    /**
     * Util meant to convert URL Query Param to MultivaluedMap<String,String> DataStructure.
     * @param str urlquery param ( Eg : "page=1&scope=openid" )
     * @return
     */
    private MultivaluedMap<String,String> decodeQueryParam(String str){
        MultivaluedMap<String,String> multivaluedMap = new MultivaluedHashMap<>();

        for(String query:str.split("&")){
            int seperatorIndex = query.indexOf("=");
            String queryParam = URLDecoder.decode(query.substring(0,seperatorIndex));
            String value = URLDecoder.decode(query.substring(seperatorIndex+1,query.length()));

            List<String> existingValueForQueryParam = multivaluedMap.getOrDefault(queryParam,new ArrayList<>());
            existingValueForQueryParam.add(value);

            multivaluedMap.put(queryParam,existingValueForQueryParam);
        }
        return multivaluedMap;
    }
}
