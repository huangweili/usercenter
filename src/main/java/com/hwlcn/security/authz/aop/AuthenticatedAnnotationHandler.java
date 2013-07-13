package com.hwlcn.security.authz.aop;

import java.lang.annotation.Annotation;

import com.hwlcn.security.authz.UnauthenticatedException;
import com.hwlcn.security.authz.annotation.RequiresAuthentication;


public class AuthenticatedAnnotationHandler extends AuthorizingAnnotationHandler {

    public AuthenticatedAnnotationHandler() {
        super(RequiresAuthentication.class);
    }

    public void assertAuthorized(Annotation a) throws UnauthenticatedException {
        if (a instanceof RequiresAuthentication && !getSubject().isAuthenticated() ) {
            throw new UnauthenticatedException( "The current Subject is not authenticated.  Access denied." );
        }
    }
}
