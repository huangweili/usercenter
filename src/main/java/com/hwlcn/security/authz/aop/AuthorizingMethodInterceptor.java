package com.hwlcn.security.authz.aop;

import com.hwlcn.security.authz.AuthorizationException;
import com.hwlcn.security.aop.MethodInterceptorSupport;
import com.hwlcn.security.aop.MethodInvocation;

public abstract class AuthorizingMethodInterceptor extends MethodInterceptorSupport {

    public Object invoke(MethodInvocation methodInvocation) throws Throwable {
        assertAuthorized(methodInvocation);
        return methodInvocation.proceed();
    }

    protected abstract void assertAuthorized(MethodInvocation methodInvocation) throws AuthorizationException;

}
