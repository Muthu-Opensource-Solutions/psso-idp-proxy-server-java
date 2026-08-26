package com.muthuopensource.jakarta.interceptors;

import com.muthuopensource.jakarta.annotations.DecodeJWSHeader;
import com.nimbusds.jose.JWSObject;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.ext.Provider;
import jakarta.ws.rs.ext.ReaderInterceptor;
import jakarta.ws.rs.ext.ReaderInterceptorContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;

@Provider
@DecodeJWSHeader
/**
 * Intercepts HTTP Request after Filter Processing and add the Authorization Header's value as HTTP Request Body
 */
public class JWSHeaderReadInterceptor implements ReaderInterceptor {
    private static Logger logger = LoggerFactory.getLogger(ReaderInterceptor.class);
    @Override
    public Object aroundReadFrom(ReaderInterceptorContext readerInterceptorContext) throws IOException, WebApplicationException {
        try {
            logger.info("JWSHeaderReadInterceptor: Decoding JWS from Authorization header");
            String authorizationHeader = readerInterceptorContext.getHeaders().getFirst("Authorization");
            logger.atDebug().log("JWSHeaderReadInterceptor: authorizationHeader : {}",authorizationHeader);
            JWSObject jwsObject = JWSObject.parse(authorizationHeader);
            InputStream inputStream = new ByteArrayInputStream(jwsObject.getPayload().toString().getBytes());
            readerInterceptorContext.setInputStream(inputStream);
            readerInterceptorContext.setMediaType(MediaType.APPLICATION_JSON_TYPE);
        } catch (ParseException e) {
            logger.error("JWSHeaderReadInterceptor: Parsing Exception Occured",e);
            throw new WebApplicationException("Invalid JWS token", 400);
        }
        return readerInterceptorContext.proceed();
    }
}
