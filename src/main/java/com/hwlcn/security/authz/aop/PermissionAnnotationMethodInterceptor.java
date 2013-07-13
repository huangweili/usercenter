package com.hwlcn.security.authz.aop;

import com.hwlcn.security.aop.AnnotationResolver;

public class PermissionAnnotationMethodInterceptor extends AuthorizingAnnotationMethodInterceptor {


    public PermissionAnnotationMethodInterceptor() {
        super( new PermissionAnnotationHandler() );
    }

    public PermissionAnnotationMethodInterceptor(AnnotationResolver resolver) {
        super( new PermissionAnnotationHandler(), resolver);
    }

}
