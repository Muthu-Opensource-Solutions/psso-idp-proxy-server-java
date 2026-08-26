package com.muthuopensource.jakarta.resources;

import com.muthuopensource.utils.PSSOUtils;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import java.io.IOException;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

@Path(PSSOUtils.PSSOEndpointURLS.JWKS_ENDPOINT_PATH)
public class PlatformSSOJWKSResource {

    /**
     * This jakarta-rs Sub-Resource Involves in Providing the Public JWK of the PlatformSSO Server Signing Key used to sign id_token
     * @return
     * @throws IOException
     * @throws ParseException
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String,List<Map<String, Object>>> handleRequest() throws Exception{
        return Map.of("keys", List.of(PSSOUtils.getServerSigningKey().toPublicJWK().toJSONObject()));
    }
}
