package com.hwlcn.security.authz.aop;

import com.hwlcn.security.aop.AnnotationResolver;



public class RoleAnnotationMethodInterceptor extends AuthorizingAnnotationMethodInterceptor {

    public RoleAnnotationMethodInterceptor() {
        super( new RoleAnnotationHandler() );
    }

    public RoleAnnotationMethodInterceptor(AnnotationResolver resolver) {
        super(new RoleAnnotationHandler(), resolver);
    }
}
