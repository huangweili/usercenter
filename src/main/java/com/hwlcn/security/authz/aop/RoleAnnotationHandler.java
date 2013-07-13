package com.hwlcn.security.authz.aop;

import com.hwlcn.security.authz.AuthorizationException;
import com.hwlcn.security.authz.annotation.Logical;
import com.hwlcn.security.authz.annotation.RequiresRoles;

import java.lang.annotation.Annotation;
import java.util.Arrays;

public class RoleAnnotationHandler extends AuthorizingAnnotationHandler {

    public RoleAnnotationHandler() {
        super(RequiresRoles.class);
    }

    public void assertAuthorized(Annotation a) throws AuthorizationException {
        if (!(a instanceof RequiresRoles)) return;

        RequiresRoles rrAnnotation = (RequiresRoles) a;
        String[] roles = rrAnnotation.value();

        if (roles.length == 1) {
            getSubject().checkRole(roles[0]);
            return;
        }
        if (Logical.AND.equals(rrAnnotation.logical())) {
            getSubject().checkRoles(Arrays.asList(roles));
            return;
        }
        if (Logical.OR.equals(rrAnnotation.logical())) {
            boolean hasAtLeastOneRole = false;
            for (String role : roles) if (getSubject().hasRole(role)) hasAtLeastOneRole = true;
            if (!hasAtLeastOneRole) getSubject().checkRole(roles[0]);
        }
    }

}
