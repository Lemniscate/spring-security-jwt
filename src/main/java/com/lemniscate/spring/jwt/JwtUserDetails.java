package com.lemniscate.spring.jwt;

import org.springframework.security.core.userdetails.UserDetails;

/**
 * Created by dave on 10/30/15.
 */
public interface JwtUserDetails extends UserDetails {

    long getExpiresMillis();
    void setExpiresMillis(long secondsFromEpoch);


    interface Marshaller {
        <E extends JwtUserDetails> E deserialize(String validatedJson, Class<E> targetType) throws Exception;
        <E extends JwtUserDetails> String serialize(E details) throws Exception;
    }
}
