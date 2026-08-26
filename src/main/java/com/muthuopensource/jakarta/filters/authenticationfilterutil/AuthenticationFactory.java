package com.muthuopensource.jakarta.filters.authenticationfilterutil;

import com.muthuopensource.utils.AuthenitcationType;

import java.util.Map;

/**
 * Factory Implementation which retrieves the Respective {@link ServerAuthenticaiton} Implementation for {@link AuthenitcationType}
 */
public class AuthenticationFactory {

    private static final Map<AuthenitcationType, ServerAuthenticaiton> authenticationTypeToImplMap = Map.of(
            AuthenitcationType.PSSO_AUTH, new PSSOAuthentication(),
            AuthenitcationType.PSSO_DEVICE_REGISTRATION_AUTH, new PSSODeviceRegistrationAuthentication(),
            AuthenitcationType.REGISTRATION_OIDC_STATE_AUTH,new RegistrationOIDCStateAuth()
    );

    public static ServerAuthenticaiton getAuthentication(AuthenitcationType type) {
        return authenticationTypeToImplMap.get(type);
    }
}
