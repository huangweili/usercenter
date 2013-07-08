package com.hwlcn.security.aop;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

public class DefaultAnnotationResolver implements AnnotationResolver {

    public Annotation getAnnotation(MethodInvocation mi, Class<? extends Annotation> clazz) {
        if (mi == null) {
            throw new IllegalArgumentException("method argument cannot be null");
        }
        Method m = mi.getMethod();
        if (m == null) {
            String msg = MethodInvocation.class.getName() + " parameter incorrectly constructed.  getMethod() returned null";
            throw new IllegalArgumentException(msg);

        }
        Annotation annotation = m.getAnnotation(clazz);
        return annotation == null ? mi.getThis().getClass().getAnnotation(clazz) : annotation;
    }
}
