package com.hwlcn.security.authz.aop;

import com.hwlcn.security.aop.AnnotationResolver;

public class GuestAnnotationMethodInterceptor extends AuthorizingAnnotationMethodInterceptor {

    public GuestAnnotationMethodInterceptor() {
        super(new GuestAnnotationHandler());
    }


    public GuestAnnotationMethodInterceptor(AnnotationResolver resolver) {
        super(new GuestAnnotationHandler(), resolver);
    }

}
