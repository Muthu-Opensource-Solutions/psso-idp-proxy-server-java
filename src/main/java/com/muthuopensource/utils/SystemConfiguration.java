package com.muthuopensource.utils;

public class SystemConfiguration {

    public static String getConfiguration(String propertyName){
        return System.getenv(propertyName);
    }

    public static String getConfigurationOrDefault(String propertyName, String defaultValue){
        String value = getConfiguration(propertyName);
        return value == null || value.isEmpty() ? defaultValue : value;
    }
}