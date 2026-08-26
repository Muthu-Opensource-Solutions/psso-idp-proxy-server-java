package com.muthuopensource.jakarta.filters;

import com.muthuopensource.jakarta.annotations.Authentication;
import com.muthuopensource.exceptions.AuthenticationException;
import com.muthuopensource.jakarta.filters.authenticationfilterutil.AuthenticationFactory;
import com.muthuopensource.jakarta.filters.authenticationfilterutil.ServerAuthenticaiton;
import com.muthuopensource.utils.AuthenitcationType;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.*;
import jakarta.ws.rs.ext.Provider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A Dynamic Filter which helps with Authenticating the HTTP Request
 */
@Provider
@Authentication
public class AuthenticationFilter implements ContainerRequestFilter {

    private static Logger logger = LoggerFactory.getLogger(AuthenticationFilter.class);

    @Context
    private ResourceInfo resourceInfo;

    @Override
    public void filter(ContainerRequestContext containerRequestContext){
        Authentication authentication = resourceInfo.getResourceClass().getAnnotation(Authentication.class);
        if(authentication==null)
            authentication = resourceInfo.getResourceMethod().getAnnotation(Authentication.class);
        AuthenitcationType authenitcationType = authentication.value();
        ServerAuthenticaiton authImpl = AuthenticationFactory.getAuthentication(authenitcationType);
        if(!authImpl.authenticate(containerRequestContext)){
            logger.error("AuthenticationFilter : Authentication Failed");
            throw new AuthenticationException("Authentication failed for type: " + authenitcationType);
        }
        logger.info("AuthenticationFilter : Authentication Passed");
    }

}
