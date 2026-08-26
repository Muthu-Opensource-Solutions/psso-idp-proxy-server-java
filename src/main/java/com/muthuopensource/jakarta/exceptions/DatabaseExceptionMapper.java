package com.muthuopensource.jakarta.exceptions;

import com.muthuopensource.exceptions.DatabaseException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

@Provider
public class DatabaseExceptionMapper implements ExceptionMapper<DatabaseException> {
    @Override
    public Response toResponse(DatabaseException e) {
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity("Database error: " + e.getMessage())
                .build();
    }
}