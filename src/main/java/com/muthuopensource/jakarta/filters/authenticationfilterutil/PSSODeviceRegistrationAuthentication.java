package com.muthuopensource.jakarta.filters.authenticationfilterutil;

import com.muthuopensource.utils.ServerUtils;
import com.muthuopensource.utils.SystemConfiguration;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.MACVerifier;
import jakarta.ws.rs.container.ContainerRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Arrays;

/**
 * Server Authentication Implementation meant to verify MAC of DeviceRegistration Request,
 * Shared Secret is securely shared to the macOS Devices using Extensible SSO Payload through MDM.So we can assume that Registration comes only from Trusted Devices
 */
class PSSODeviceRegistrationAuthentication implements ServerAuthenticaiton{
    private static Logger logger = LoggerFactory.getLogger(PSSODeviceRegistrationAuthentication.class);
    @Override
    public boolean authenticate(ContainerRequestContext containerRequestContext) {
        try{
            logger.info("PSSODeviceRegistrationAuthentication : Authenticating the request for PSSO device registration");
            String authorizationHeader = containerRequestContext.getHeaders().getFirst("Authorization");
            JWSObject jwsObject = JWSObject.parse(authorizationHeader);

            //Getting DeviceRegistration Shared Secret between client-server
            String pssoDeviceRegistrationSecret = SystemConfiguration.getConfiguration(ServerUtils.PropertyConstants.PSSO_HMAC_SECRET_KEY);

            //Computing SHA-256 since Nimbus JOSE Requires the input byte[] to be atleast 256 bit length
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] shaDigest = digest.digest(pssoDeviceRegistrationSecret.getBytes(StandardCharsets.UTF_8));
            return jwsObject.verify(new MACVerifier(shaDigest));

        } catch (JOSEException | ParseException e){
            logger.error("PSSODeviceRegistrationAuthentication : Error while verifying the JWS signature",e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        logger.info("PSSODeviceRegistrationAuthentication : Authentication failed for PSSO device registration request {}",containerRequestContext.getUriInfo().toString());
        return false;
    }

}
