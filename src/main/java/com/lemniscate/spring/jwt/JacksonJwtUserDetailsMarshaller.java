package com.lemniscate.spring.jwt;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Created by dave on 10/30/15.
 */
public class JacksonJwtUserDetailsMarshaller <E extends JwtUserDetails> implements JwtUserDetails.Marshaller<E> {

    @Autowired
    public ObjectMapper objectMapper;

    @Override
    public E deserialize(String validatedJson, Class<E> targetType) throws Exception{
        E details = objectMapper
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .readValue(validatedJson, targetType);
        return details;
    }

    @Override
    public String serialize(E details) throws Exception{
        return objectMapper.writeValueAsString(details);
    }
}
