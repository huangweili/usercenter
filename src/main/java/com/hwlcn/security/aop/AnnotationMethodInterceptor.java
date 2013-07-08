package com.hwlcn.security.aop;

import java.lang.annotation.Annotation;

public abstract class AnnotationMethodInterceptor extends MethodInterceptorSupport {

    private AnnotationHandler handler;


    private AnnotationResolver resolver;


    public AnnotationMethodInterceptor(AnnotationHandler handler) {
        this(handler, new DefaultAnnotationResolver());
    }

    public AnnotationMethodInterceptor(AnnotationHandler handler, AnnotationResolver resolver) {
        if (handler == null) {
            throw new IllegalArgumentException("AnnotationHandler argument cannot be null.");
        }
        setHandler(handler);
        setResolver(resolver != null ? resolver : new DefaultAnnotationResolver());
    }

    public AnnotationHandler getHandler() {
        return handler;
    }

    public void setHandler(AnnotationHandler handler) {
        this.handler = handler;
    }

    public AnnotationResolver getResolver() {
        return resolver;
    }

    public void setResolver(AnnotationResolver resolver) {
        this.resolver = resolver;
    }

    public boolean supports(MethodInvocation mi) {
        return getAnnotation(mi) != null;
    }

    protected Annotation getAnnotation(MethodInvocation mi) {
        return getResolver().getAnnotation(mi, getHandler().getAnnotationClass());
    }
}
