package com.lemniscate.spring.jwt;

import org.joda.time.DateTime;
import org.joda.time.Minutes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import javax.annotation.PostConstruct;
import java.util.logging.Logger;

/**
 * Created by dave on 4/7/15.
 */
public interface JwtService<E extends JwtUserDetails> extends AuthenticationProvider {

    String encodeDetails(E details);

    E parseDetails(String json);

    class JwtServiceImpl<E extends JwtUserDetails> implements JwtService<E> {

        private static final Logger LOGGER = Logger.getLogger(JwtServiceImpl.class.getName());

        @Value("${app.security.jwt.phrase}")
        private String jwtPhrase;

        @Value("${app.security.jwt.identifier:X-JWT-TOKEN}")
        private String jwtIdentifier;

        private Class<E> detailsClass;

        private MacSigner hmac;

        @Autowired(required = false)
        private JwtUserDetails.Marshaller<E> marshaller;

        @Autowired(required = false)
        private AuthenticationEventPublisher eventPublisher;


        public JwtServiceImpl(Class<E> detailsClass){
            this.detailsClass = detailsClass;
        }


        @PostConstruct
        public void init() {
            hmac = new MacSigner(jwtPhrase);
        }



        @Override
        public final Authentication authenticate(Authentication auth) throws AuthenticationException {
            try {
                return doAuthenticate(auth);
            }catch(AuthenticationException e){
                Authentication ctxa = SecurityContextHolder.getContext().getAuthentication();
                if( ctxa == null ){
                    ctxa = auth;
                }
                eventPublisher.publishAuthenticationFailure(e, ctxa);
                throw e;
            }catch(RuntimeException e){
                AuthenticationServiceException ex = new AuthenticationServiceException("An unexpected error occurred while processing a JWT session", e);
                Authentication ctxa = SecurityContextHolder.getContext().getAuthentication();
                if( ctxa == null ){
                    ctxa = auth;
                }
                eventPublisher.publishAuthenticationFailure(ex, ctxa);
                throw ex;
            }
        }


        protected Authentication doAuthenticate(Authentication authentication) throws AuthenticationException {
            PreAuthenticatedAuthenticationToken token = (PreAuthenticatedAuthenticationToken) authentication;
            token.setAuthenticated(true);

            Object principal = token.getPrincipal();
            E details = null;

            if( principal instanceof String){
                // Handle a string passed from downstream (common usage)
                details = parseStringPrincipal((String) principal);
            }else if(principal instanceof JwtUserDetails ){
                // if they passed us a UserAccountDetails, consider it good
                details = (E) principal;
            }

            // opt out early if we're null
            if( details == null ){
//                throw new InsufficientAuthenticationException("Could not determine user details");
                return authentication;
            }

            DateTime expires = new DateTime(details.getExpiresMillis());
            int minutes = Minutes.minutesBetween(new DateTime(), expires).getMinutes();
            if (minutes < 0) {
                throw new JwtTokenExpiredException(String.format("Your session expired %s minutes ago", minutes));
            }

            // TODO do we want to refresh stale from the DB on each request?
            PreAuthenticatedAuthenticationToken result = new PreAuthenticatedAuthenticationToken(details, null, details.getAuthorities());
            return result;
        }

        protected E parseStringPrincipal(String jwt){
            // explicitly fail if there was no principal found earlier
            if( jwt.equals(JwtTokenAuthenticationFilter.NO_ACCESS) ) {
                return null;
            }else if (!jwt.startsWith("Bearer ")) {
                throw new AuthenticationServiceException("Invalid Authorization token. Format should be: Bearer [Token]");
            }

            jwt = jwt.substring("Bearer ".length());
            return parseDetails(jwt);
        }


        @Override
        public String encodeDetails(E details) {
            try {
                String json = marshaller.serialize(details);
                Jwt jwt = JwtHelper.encode(json, hmac);
                String encoded = jwt.getEncoded();
                return encoded;
            } catch (Exception e) {
                throw new AuthenticationServiceException("Failed encoding JWT details", e);
            }
        }

        @Override
        public E parseDetails(String json) {
            try {
                Jwt res = JwtHelper.decode(json);
                res.verifySignature(hmac);
                String resultJson = res.getClaims();
                E details = marshaller.deserialize(resultJson, detailsClass);
                return details;
            }catch(Exception e){
                throw new JwtParseException("Failed parsing JwtUserAccountDetails", e);
            }
        }


        @Override
        public boolean supports(Class<?> authentication) {
            return PreAuthenticatedAuthenticationToken.class.equals(authentication);
        }

        public static class JwtParseException extends AuthenticationException {
            public JwtParseException(String msg, Throwable t) {
                super(msg, t);
            }
        }

        public static class JwtTokenExpiredException extends AuthenticationException {
            public JwtTokenExpiredException(String msg) {
                super(msg);
            }
        }
    }
}