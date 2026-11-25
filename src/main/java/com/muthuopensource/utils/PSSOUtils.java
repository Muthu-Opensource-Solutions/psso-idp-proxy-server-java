package com.muthuopensource.utils;

import com.nimbusds.jose.jwk.ECKey;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;

import java.net.URI;
import java.security.SecureRandom;
import java.util.Base64;

public class PSSOUtils {

    private static final SecureRandom secureRandom = new SecureRandom();
    private static ECKey serverSigningKey = null;

    public static class PSSOEndpointURLS {
        public static final String DEVICE_REGISTRATION_PATH = "psso/deviceRegistration";
        public static final String TOKEN_ENDPOINT_PATH = "psso/token";
        public static final String JWKS_ENDPOINT_PATH = "psso/jwks";
        public static final String NONCE_ENDPOINT_PATH = "psso/nonce";
        public static final String KEY_ENDPOINT_PATH = "psso/key";
    }

    public static class CommonServerURLs{
        public static final String APPLE_APP_SITE_ASSOCIATION_URL = ".well-known/apple-app-site-association";
    }

    public static class OIDCEndpointURLs{
        public static final String OIDC = "oidc";
        public static final String USER_REGISTRATION_DISCOVERY_PATH = "authCode/discovery";
        public static final String USER_REGISTRATION_CALLBACK_PATH = "authCode/userRegistrationCallback";
        public static final String PSSO_OPENID_TYPE_AUTHORIZE_PATH = "webAuth/authorize";
        public static final String PSSO_OPENID_TYPE_CALLBACK_PATH = "webAuth/callback";
    }

    public static class FileNames{
        public static final String deviceEncryptionKey = "deviceEncryptionKey.json";
        public static final String deviceSingingKey = "deviceSigningKey.json";
    }

    public static class DirectoryNames{
        //directory used to maintain Registration Keys, Server Signing Keys
        public static final String DATA_DIRECTORY = "/data";
    }

    public static ECKey getServerSigningKey(){
        if(serverSigningKey==null){
            serverSigningKey = ServerUtils.generateServerSigningKey();
        }
        return serverSigningKey;
    }

    public static enum PSSOGrantTypes{
        PASSWORD("password"),
        OPENID("urn:ietf:params:oauth:grant-type:token-exchange");

        private final String type;
        PSSOGrantTypes(String type){
            this.type = type;
        }

        public boolean equals(String valueToCompare){
            return this.type.equals(valueToCompare);
        }
    }

    /**
     * Generates a cryptographically secure random byte array of specified length.
     * @param byteLength Number of random bytes to generate
     * @return byte[] containing random bytes
     */
    public static byte[] generateRandomBytes(int byteLength) {
        byte[] bytes = new byte[byteLength];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    /**
     * Generates a cryptographically secure URL-safe Base64-encoded random state string.
     * @param byteLength Number of random bytes
     * @return Base64 URL-safe encoded String without padding
     */
    public static String generateRandomState(int byteLength) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(generateRandomBytes(byteLength));
    }

    /**
     * Generates a 16-byte cryptographically secure URL-safe Base64-encoded random state string.
     * @return Base64 URL-safe encoded String
     */
    public static String generateRandomState() {
        return generateRandomState(16);
    }

    /**
     * Generates the callback URI for PSSO WebAuth OpenID flow using the given UriInfo.
     * @param uriInfo UriInfo from JAX-RS context
     * @return URI pointing to /oidc/webAuth/callback
     */
    public static URI getPSSOWebAuthCallbackURI(UriInfo uriInfo) {
        return getPSSOWebAuthCallbackURI(uriInfo.getBaseUri());
    }

    /**
     * Generates the callback URI for PSSO WebAuth OpenID flow using the given base URI.
     * @param baseUri Base URI of the server
     * @return URI pointing to /oidc/webAuth/callback
     */
    public static URI getPSSOWebAuthCallbackURI(URI baseUri) {
        return UriBuilder.fromUri(baseUri)
                .path(OIDCEndpointURLs.OIDC)
                .path(OIDCEndpointURLs.PSSO_OPENID_TYPE_CALLBACK_PATH)
                .build();
    }

    public static final String STATE_COOKIE_NAME = "X-State-Cookie";

    /**
     * Creates a secure state cookie with path="/" for Anti-CSRF validation.
     * @param state The state value to store
     * @return NewCookie configured with path="/", HttpOnly=true, Secure=true, SameSite=LAX
     */
    public static NewCookie createStateCookie(String state) {
        return new NewCookie.Builder(STATE_COOKIE_NAME)
                .value(state)
                .path("/")
                .secure(true)
                .httpOnly(true)
                .sameSite(NewCookie.SameSite.LAX)
                .build();
    }


    public static String getHTMLBasedWebPageRedirectXML(String redirectURL){
        return   """
                    <!DOCTYPE html> 
                    <html>
                    <head>
                        <script>
                            window.location.replace("%s");
                        </script>
                    </head>
                    <body></body>
                    </html>""".formatted(redirectURL);
    }

    private PSSOUtils(){}

}
