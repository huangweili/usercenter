package com.hwlcn.security.authz.aop;

import com.hwlcn.security.authz.AuthorizationException;
import com.hwlcn.security.authz.annotation.Logical;
import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.authz.annotation.RequiresPermissions;

import java.lang.annotation.Annotation;


public class PermissionAnnotationHandler extends AuthorizingAnnotationHandler {

    public PermissionAnnotationHandler() {
        super(RequiresPermissions.class);
    }

    protected String[] getAnnotationValue(Annotation a) {
        RequiresPermissions rpAnnotation = (RequiresPermissions) a;
        return rpAnnotation.value();
    }

    public void assertAuthorized(Annotation a) throws AuthorizationException {
        if (!(a instanceof RequiresPermissions)) return;

        RequiresPermissions rpAnnotation = (RequiresPermissions) a;
        String[] perms = getAnnotationValue(a);
        Subject subject = getSubject();

        if (perms.length == 1) {
            subject.checkPermission(perms[0]);
            return;
        }
        if (Logical.AND.equals(rpAnnotation.logical())) {
            getSubject().checkPermissions(perms);
            return;
        }
        if (Logical.OR.equals(rpAnnotation.logical())) {
            boolean hasAtLeastOnePermission = false;
            for (String permission : perms) if (getSubject().isPermitted(permission)) hasAtLeastOnePermission = true;
            if (!hasAtLeastOnePermission) getSubject().checkPermission(perms[0]);
            
        }
    }
}
