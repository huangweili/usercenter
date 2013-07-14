package com.hwlcn.security.spring.aop;


import com.hwlcn.security.aop.AnnotationResolver;
import com.hwlcn.security.aop.MethodInvocation;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.util.ClassUtils;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

public class SpringAnnotationResolver implements AnnotationResolver {

    public Annotation getAnnotation(MethodInvocation mi, Class<? extends Annotation> clazz) {
        Method m = mi.getMethod();

        Annotation a = AnnotationUtils.findAnnotation(m, clazz);
        if (a != null) return a;

        Class<?> targetClass = mi.getThis().getClass();
        m = ClassUtils.getMostSpecificMethod(m, targetClass);
        a = AnnotationUtils.findAnnotation(m, clazz);
        if (a != null) return a;
        return AnnotationUtils.findAnnotation(mi.getThis().getClass(), clazz);
    }
}
