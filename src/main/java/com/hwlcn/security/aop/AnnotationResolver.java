package com.hwlcn.security.aop;

import java.lang.annotation.Annotation;

public interface AnnotationResolver {


    Annotation getAnnotation(MethodInvocation mi, Class<? extends Annotation> clazz);
}
