package com.hwlcn.security.spring.security.interceptor;

import com.hwlcn.security.aop.AnnotationResolver;
import com.hwlcn.security.aop.MethodInterceptor;
import com.hwlcn.security.aop.MethodInvocation;

import com.hwlcn.security.authz.aop.*;
import com.hwlcn.security.spring.aop.SpringAnnotationResolver;
import org.aopalliance.aop.Advice;

import java.lang.reflect.Method;
import java.util.ArrayList;

import java.util.List;

public class AopAllianceAnnotationsAuthorizingMethodInterceptor
        extends AnnotationsAuthorizingMethodInterceptor implements MethodInterceptor,Advice {

    public AopAllianceAnnotationsAuthorizingMethodInterceptor() {
        List<AuthorizingAnnotationMethodInterceptor> interceptors =
                new ArrayList<AuthorizingAnnotationMethodInterceptor>(5);

        AnnotationResolver resolver = new SpringAnnotationResolver();
        interceptors.add(new RoleAnnotationMethodInterceptor(resolver));
        interceptors.add(new PermissionAnnotationMethodInterceptor(resolver));
        interceptors.add(new AuthenticatedAnnotationMethodInterceptor(resolver));
        interceptors.add(new UserAnnotationMethodInterceptor(resolver));
        interceptors.add(new GuestAnnotationMethodInterceptor(resolver));

        setMethodInterceptors(interceptors);
    }

    protected MethodInvocation createMethodInvocation(Object implSpecificMethodInvocation) {
        final MethodInvocation mi = (MethodInvocation) implSpecificMethodInvocation;

        return new MethodInvocation() {
            public Method getMethod() {
                return mi.getMethod();
            }

            public Object[] getArguments() {
                return mi.getArguments();
            }

            public String toString() {
                return "Method invocation [" + mi.getMethod() + "]";
            }

            public Object proceed() throws Throwable {
                return mi.proceed();
            }

            public Object getThis() {
                return mi.getThis();
            }
        };
    }


    protected Object continueInvocation(Object aopAllianceMethodInvocation) throws Throwable {
        MethodInvocation mi = (MethodInvocation) aopAllianceMethodInvocation;
        return mi.proceed();
    }

    public Object invoke(MethodInvocation methodInvocation) throws Throwable {
        MethodInvocation mi = createMethodInvocation(methodInvocation);
        return super.invoke(mi);
    }
}
