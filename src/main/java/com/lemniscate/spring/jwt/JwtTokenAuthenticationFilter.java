package com.lemniscate.spring.jwt;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;
import org.springframework.web.util.WebUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

/**
 * Created by dave on 4/8/15.
 */
public class JwtTokenAuthenticationFilter extends RequestHeaderAuthenticationFilter {

    @Value("${app.security.jwt.identifier:X-JWT-TOKEN}")
    private String jwtIdentifier;

    public static final String NO_ACCESS = "UNAUTHORIZED";
    private String principalRequestHeader;

    @Override
    public void afterPropertiesSet() {
        super.afterPropertiesSet();

        // if someone manually specified a header, use the same name for the cookie
        if( principalRequestHeader == null ){
            this.setPrincipalRequestHeader(jwtIdentifier);
        }else{
            jwtIdentifier = principalRequestHeader;
        }
    }

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        Object p = super.getPreAuthenticatedPrincipal(request);
        if( p == null && jwtIdentifier != null ){
            Cookie cookie = WebUtils.getCookie(request, jwtIdentifier);
            if( cookie != null ){
                p = "Bearer " + cookie.getValue();
            }
        }else if(p instanceof String){
            p = "Bearer " + p;
        }

        return p == null ? NO_ACCESS : p;
    }

    @Override
    public void setPrincipalRequestHeader(String principalRequestHeader) {
        super.setPrincipalRequestHeader(principalRequestHeader);
        this.principalRequestHeader = principalRequestHeader;
    }

    @Override
    public void setCredentialsRequestHeader(String credentialsRequestHeader) {
        throw new UnsupportedOperationException("Method not supported");
    }

}
