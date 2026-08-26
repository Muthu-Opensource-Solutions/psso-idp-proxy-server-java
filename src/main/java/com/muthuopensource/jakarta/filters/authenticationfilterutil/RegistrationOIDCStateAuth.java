package com.muthuopensource.jakarta.filters.authenticationfilterutil;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MultivaluedMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * ServerAuthenticaiton which used to verify the State Parameter of OIDC Callbacks to Server with Browser Stored Cookies
 */
class RegistrationOIDCStateAuth implements ServerAuthenticaiton{
    private Logger logger = LoggerFactory.getLogger(RegistrationOIDCStateAuth.class);
    @Override
    public boolean authenticate(ContainerRequestContext containerRequestContext) {
        MultivaluedMap<String,String> queryParamMap = containerRequestContext.getUriInfo().getQueryParameters();
        List<String> stateList = queryParamMap.get("state");
        if(stateList == null || stateList.size() != 1) {
            logger.error("RegistrationOIDCStateAuth : State Param is empty in HTTP Request");
            return false;
        }
        String state = stateList.getFirst();
        String stateFromCookie = containerRequestContext.getCookies().get("X-State-Cookie").getValue();
        if(!state.equals(stateFromCookie)){
            logger.error("RegistrationOIDCStateAuth : State Param : {} X-State-Cookie : {} is not matching",state,stateFromCookie);
            return false;
        }
        return true;
    }
}
