package com.hwlcn.security.authz.aop;

import java.lang.annotation.Annotation;

import com.hwlcn.security.authz.AuthorizationException;
import com.hwlcn.security.authz.UnauthenticatedException;
import com.hwlcn.security.authz.annotation.RequiresUser;



public class UserAnnotationHandler extends AuthorizingAnnotationHandler {

    public UserAnnotationHandler() {
        super(RequiresUser.class);
    }

    public void assertAuthorized(Annotation a) throws AuthorizationException {
        if (a instanceof RequiresUser && getSubject().getPrincipal() == null) {
            throw new UnauthenticatedException("Attempting to perform a user-only operation.  The current Subject is " +
                    "not a user (they haven't been authenticated or remembered from a previous login).  " +
                    "Access denied.");
        }
    }
}
