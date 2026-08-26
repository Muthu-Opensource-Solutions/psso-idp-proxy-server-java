package com.muthuopensource.jakarta.resources;

import com.muthuopensource.jakarta.annotations.Authentication;
import com.muthuopensource.jakarta.annotations.DecodeJWSHeader;
import com.muthuopensource.beans.DeviceRegistrationBean;
import com.muthuopensource.exceptions.DatabaseException;
import com.muthuopensource.service.PlatformSSODeviceService;
import com.muthuopensource.utils.AuthenitcationType;
import com.muthuopensource.utils.PSSOUtils;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Jakarta Resource Created to handle API related to PSSO DeviceRegistration
 */
@Path(PSSOUtils.PSSOEndpointURLS.DEVICE_REGISTRATION_PATH)
@Authentication(AuthenitcationType.PSSO_DEVICE_REGISTRATION_AUTH)
@DecodeJWSHeader
public class PlatformSSODeviceRegistrationResource {

    Logger logger = LoggerFactory.getLogger(PlatformSSODeviceRegistrationResource.class);
    /**
     * This jakarta-rs Sub-Resource Involves in Registering, Re-Registering the macOS Device as Part of PlatformSSO Device Registration Flow.
     * It will upsert the device registration keys in the database. which can be used in Future for Device Authentication and Authorization
     * @param deviceRegistrationData
     * @return
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response handleRequest(DeviceRegistrationBean deviceRegistrationData) {
        logger.info("PlatformSSODeviceRegistrationResource : Received Device Registration Request data : {}",deviceRegistrationData.toString());
        try {
            PlatformSSODeviceService.getInstance().addOrUpdateDeviceRegistrationKeys(deviceRegistrationData);
            return Response.status(Response.Status.ACCEPTED)
                    .build();
        } catch (Exception e){
            logger.error("PlatformSSODeviceRegistrationResource : Error Occured while Upserting Device Registration");
            throw new DatabaseException("Failed to upsert device registration keys for device: " + deviceRegistrationData.getSerialNumber());
        }
    }
}
