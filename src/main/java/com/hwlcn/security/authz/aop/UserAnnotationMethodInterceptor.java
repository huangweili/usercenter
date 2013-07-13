package com.hwlcn.security.authz.aop;

import com.hwlcn.security.aop.AnnotationResolver;


public class UserAnnotationMethodInterceptor extends AuthorizingAnnotationMethodInterceptor {

    public UserAnnotationMethodInterceptor() {
        super( new UserAnnotationHandler() );
    }

    public UserAnnotationMethodInterceptor(AnnotationResolver resolver) {
        super(new UserAnnotationHandler(), resolver);
    }

}
