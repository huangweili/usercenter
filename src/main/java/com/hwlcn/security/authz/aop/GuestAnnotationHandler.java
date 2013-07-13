package com.hwlcn.security.authz.aop;

import java.lang.annotation.Annotation;

import com.hwlcn.security.authz.AuthorizationException;
import com.hwlcn.security.authz.UnauthenticatedException;
import com.hwlcn.security.authz.annotation.RequiresGuest;



public class GuestAnnotationHandler extends AuthorizingAnnotationHandler {

    public GuestAnnotationHandler() {
        super(RequiresGuest.class);
    }

    public void assertAuthorized(Annotation a) throws AuthorizationException {
        if (a instanceof RequiresGuest && getSubject().getPrincipal() != null) {
            throw new UnauthenticatedException("Attempting to perform a guest-only operation.  The current Subject is " +
                    "not a guest (they have been authenticated or remembered from a previous login).  Access " +
                    "denied.");
        }
    }
}
