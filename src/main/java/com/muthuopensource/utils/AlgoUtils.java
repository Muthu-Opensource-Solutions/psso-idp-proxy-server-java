package com.muthuopensource.utils;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;

import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;

public class AlgoUtils {
    /**
     * Util meant to convert URL Query Param to MultivaluedMap<String,String> DataStructure.
     * @param str urlquery param ( Eg : "page=1&scope=openid" )
     * @return
     */
    public static MultivaluedMap<String,String> decodeQueryParam(String str){
        MultivaluedMap<String,String> multivaluedMap = new MultivaluedHashMap<>();

        for(String query:str.split("&")){
            int seperatorIndex = query.indexOf("=");
            String queryParam = URLDecoder.decode(query.substring(0,seperatorIndex));
            String value = URLDecoder.decode(query.substring(seperatorIndex+1,query.length()));

            List<String> existingValueForQueryParam = multivaluedMap.getOrDefault(queryParam,new ArrayList<>());
            existingValueForQueryParam.add(value);

            multivaluedMap.put(queryParam,existingValueForQueryParam);
        }
        return multivaluedMap;
    }
}
