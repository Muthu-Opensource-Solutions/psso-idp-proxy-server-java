package com.muthuopensource.jakarta.resources;


import com.muthuopensource.utils.PSSOUtils;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;


/**
 * Jakarta Resource Created for Serving Apple App Site Association File
 */
@Path(PSSOUtils.CommonServerURLs.APPLE_APP_SITE_ASSOCIATION_URL)
public class AppleAppSiteAssociationResource {

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public Response getAppleAppSiteAssoicationResponse(){
        String response = "{\"authsrv\":{\"apps\":[\"84V944P795.com.muthuopensource.psso-client-swiftui\"]}}";
        return Response.ok(response,MediaType.TEXT_PLAIN)
                .build();
    }
}
