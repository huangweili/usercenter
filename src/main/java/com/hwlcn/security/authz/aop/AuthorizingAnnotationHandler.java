package com.hwlcn.security.authz.aop;

import java.lang.annotation.Annotation;

import com.hwlcn.security.aop.AnnotationHandler;
import com.hwlcn.security.authz.AuthorizationException;

public abstract class AuthorizingAnnotationHandler extends AnnotationHandler {

    public AuthorizingAnnotationHandler(Class<? extends Annotation> annotationClass) {
        super(annotationClass);
    }


    public abstract void assertAuthorized(Annotation a) throws AuthorizationException;
}
