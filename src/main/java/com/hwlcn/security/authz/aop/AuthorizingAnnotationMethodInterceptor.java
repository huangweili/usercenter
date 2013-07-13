package com.hwlcn.security.authz.aop;

import com.hwlcn.security.aop.AnnotationResolver;
import com.hwlcn.security.authz.AuthorizationException;
import com.hwlcn.security.aop.AnnotationMethodInterceptor;
import com.hwlcn.security.aop.MethodInvocation;


public abstract class AuthorizingAnnotationMethodInterceptor extends AnnotationMethodInterceptor
{
    
    public AuthorizingAnnotationMethodInterceptor( AuthorizingAnnotationHandler handler ) {
        super(handler);
    }

    public AuthorizingAnnotationMethodInterceptor( AuthorizingAnnotationHandler handler,
                                                   AnnotationResolver resolver) {
        super(handler, resolver);
    }

    public Object invoke(MethodInvocation methodInvocation) throws Throwable {
        assertAuthorized(methodInvocation);
        return methodInvocation.proceed();
    }

    public void assertAuthorized(MethodInvocation mi) throws AuthorizationException {
        try {
            ((AuthorizingAnnotationHandler)getHandler()).assertAuthorized(getAnnotation(mi));
        }
        catch(AuthorizationException ae) {
            if (ae.getCause() == null) ae.initCause(new AuthorizationException("Not authorized to invoke method: " + mi.getMethod()));
            throw ae;
        }         
    }
}
