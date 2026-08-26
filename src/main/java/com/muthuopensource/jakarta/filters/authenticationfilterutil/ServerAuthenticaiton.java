package com.muthuopensource.jakarta.filters.authenticationfilterutil;

import jakarta.ws.rs.container.ContainerRequestContext;

public interface ServerAuthenticaiton {
    boolean authenticate(ContainerRequestContext containerRequestContext);
}
