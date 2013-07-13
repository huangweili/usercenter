package com.hwlcn.security.authz.aop;

import com.hwlcn.security.aop.AnnotationResolver;

public class AuthenticatedAnnotationMethodInterceptor extends AuthorizingAnnotationMethodInterceptor {

    public AuthenticatedAnnotationMethodInterceptor() {
        super(new AuthenticatedAnnotationHandler());
    }

    public AuthenticatedAnnotationMethodInterceptor(AnnotationResolver resolver) {
        super(new AuthenticatedAnnotationHandler(), resolver);
    }
}
