package com.muthuopensource.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.muthuopensource.exceptions.DatabaseException;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

public class PlatformSSONonceService {

    private static PlatformSSONonceService instance = null;

    public static PlatformSSONonceService getInstance(){
        if (instance==null){
            instance = new PlatformSSONonceService();
        }
        return instance;
    }

    private PlatformSSONonceService(){}

    private Cache<String,String> nonceCache = Caffeine.newBuilder()
            .expireAfterWrite(5, TimeUnit.MINUTES)   // TTL requirement
            .maximumSize(500_000)                    // Size Eviction Max Size
            .build();

    public String generateNonce(String serialNumber) throws DatabaseException {
        byte[] nonceBytes = new byte[16];
        new SecureRandom().nextBytes(nonceBytes);
        String nonceString = serialNumber + ":" + Base64.getEncoder().encodeToString(nonceBytes);
        nonceCache.put(nonceString,nonceString);
        return nonceString;
    }
    public boolean verifyNonceAndDelete(String nonce,String serialNumber){
        String nonceFromCache = nonceCache.getIfPresent(nonce);
        if(nonceFromCache==null || nonceFromCache.isEmpty() || !nonceFromCache.equals(nonce))
            return false;
        if(!nonce.split(":")[0].equals(serialNumber))
            return false;
        nonceCache.invalidate(nonce);
        return true;
    }

}
