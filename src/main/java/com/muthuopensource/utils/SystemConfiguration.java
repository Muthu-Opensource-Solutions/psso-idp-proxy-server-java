package com.muthuopensource.utils;

import java.util.HashMap;
import java.util.Map;

public class SystemConfiguration {

    private static Map<String,String> systemConfigurationMap;
    static {
        systemConfigurationMap = new HashMap<>();
//        systemConfigurationMap.put("PSSO_AUTH_CODE_GRANT_OIDC_PROVIDER_URL","https://integrator-6948502.okta.com");
//        systemConfigurationMap.put("PSSO_AUTH_CODE_GRANT_OIDC_CLIENT_ID","0oa14rvdkvlmYfoxu698");
//        systemConfigurationMap.put("PSSO_AUTH_CODE_GRANT_OIDC_CLIENT_SECRET","ITKUietQg-KAJ3YDyXRtLLhkPJwiMCQ0I2zKIl7IVizFaKwr6SC928QXpfdt92vV");
//        systemConfigurationMap.put("PSSO_SERVER_KEY_PROTECTION_PASSWORD","MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBL0Z7g5k1J6x3F8l5z9V1K5Z");
//        systemConfigurationMap.put("PSSO_ROPG_OIDC_PROVIDER_URL","https://integrator-6948502.okta.com");
//        systemConfigurationMap.put("PSSO_ROPG_CLIENT_ID","0oa14rvdkvlmYfoxu698");
//        systemConfigurationMap.put("PSSO_ROPG_CLIENT_SECRET","ITKUietQg-KAJ3YDyXRtLLhkPJwiMCQ0I2zKIl7IVizFaKwr6SC928QXpfdt92vV");
//        systemConfigurationMap.put("PSSO_HMAC_SECRET_KEY","AMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBL0Z7g5k1J6x3F8l5z9V1K5Z");
//        systemConfigurationMap.put("SERVER_FILES_STORAGE_DIRECTORY","/opt/psso");
    }

    public static String getConfiguration(String propertyName){
        return System.getenv(propertyName);
    }

    public static String getConfigurationOrDefault(String propertyName, String defaultValue){
        String value = getConfiguration(propertyName);
        return value == null || value.isEmpty() ? defaultValue : value;
    }
}