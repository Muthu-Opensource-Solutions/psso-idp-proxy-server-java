package com.muthuopensource.jakarta.exceptions;

import com.muthuopensource.exceptions.OauthException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

@Provider
public class OauthExceptionMapper implements ExceptionMapper<OauthException> {
    @Override
    public Response toResponse(OauthException e) {
        return Response.status(Response.Status.UNAUTHORIZED)
                .entity("OAuth error: " + e.getMessage())
                .build();
    }
}
