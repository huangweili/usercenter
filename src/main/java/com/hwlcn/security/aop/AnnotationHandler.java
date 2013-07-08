package com.hwlcn.security.aop;

import java.lang.annotation.Annotation;

import com.hwlcn.security.SecurityUtils;
import com.hwlcn.security.subject.Subject;


public abstract class AnnotationHandler {

    protected Class<? extends Annotation> annotationClass;

    public AnnotationHandler(Class<? extends Annotation> annotationClass) {
        setAnnotationClass(annotationClass);
    }

    protected Subject getSubject() {
        return SecurityUtils.getSubject();
    }

    protected void setAnnotationClass(Class<? extends Annotation> annotationClass)
            throws IllegalArgumentException {
        if (annotationClass == null) {
            String msg = "annotationClass argument cannot be null";
            throw new IllegalArgumentException(msg);
        }
        this.annotationClass = annotationClass;
    }

    public Class<? extends Annotation> getAnnotationClass() {
        return this.annotationClass;
    }

}
