package com.muthuopensource.utils;

import com.nimbusds.jose.jwk.ECKey;

public class PSSOUtils {

    private static ECKey serverSigningKey = null;

    public class PSSOEndpointURLS {
        public static final String DEVICE_REGISTRATION_PATH = "psso/deviceRegistration";
        public static final String TOKEN_ENDPOINT_PATH = "psso/token";
        public static final String JWKS_ENDPOINT_PATH = "psso/jwks";
        public static final String NONCE_ENDPOINT_PATH = "psso/nonce";
        public static final String KEY_ENDPOINT_PATH = "psso/key";
    }

    public class CommonServerURLs{
        public static final String APPLE_APP_SITE_ASSOCIATION_URL = ".well-known/apple-app-site-association";
    }

    public class OIDCEndpointURLs{
        public static final String OIDC = "oidc";
        public static final String USER_REGISTRATION_DISCOVERY_PATH = "authCode/discovery";
        public static final String USER_REGISTRATION_CALLBACK_PATH = "authCode/userRegistrationCallback";
        public static final String PSSO_OPENID_TYPE_DISCOVERY_PATH = "webAuth/discovery";
    }

    public class FileNames{
        public static final String deviceEncryptionKey = "deviceEncryptionKey.json";
        public static final String deviceSingingKey = "deviceSigningKey.json";
    }

    public class DirectoryNames{
        //directory used to maintain Registration Keys, Server Signing Keys
        public static final String DATA_DIRECTORY = "/data";
    }

    public static ECKey getServerSigningKey() throws Exception{
        if(serverSigningKey==null){
            serverSigningKey = ServerUtils.generateServerSigningKey();
        }
        return serverSigningKey;
    }

    public static enum PSSOGrantTypes{
        PASSWORD("password"),
        OPENID("urn:ietf:params:oauth:grant-type:token-exchange");

        private String type;
        PSSOGrantTypes(String type){
            this.type = type;
        }

        public boolean equals(String valueToCompare){
            return this.type.equals(valueToCompare);
        }
    }

    private PSSOUtils(){}

}
