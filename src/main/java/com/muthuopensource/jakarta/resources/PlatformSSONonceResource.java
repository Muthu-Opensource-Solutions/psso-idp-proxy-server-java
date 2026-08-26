package com.muthuopensource.jakarta.resources;

import com.muthuopensource.exceptions.DatabaseException;
import com.muthuopensource.service.PlatformSSONonceService;
import com.muthuopensource.utils.PSSOUtils;
import jakarta.ws.rs.*;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Jakarta Resource Created to handle PSSO Nonce Request <a href="https://developer.apple.com/documentation/authenticationservices/obtaining-a-server-nonce">API Documentation</a>
 */
@Path(PSSOUtils.PSSOEndpointURLS.NONCE_ENDPOINT_PATH)
public class PlatformSSONonceResource {

    private static Logger logger = LoggerFactory.getLogger(PlatformSSONonceResource.class);
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String,String> handleRequest(@FormParam("serialNumber") String serialNumber) throws DatabaseException {
        logger.info("PlatformSSONonceResource : Received Nonce Request from device SN : {}",serialNumber);
        return Map.of("nonce", PlatformSSONonceService.getInstance().generateNonce(serialNumber));
    }

}