package com.hwlcn.core.annotation;

import com.hwlcn.ldap.util.ThreadSafetyLevel;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Documented()
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.TYPE, ElementType.METHOD })
public @interface ThreadSafety
{
  ThreadSafetyLevel level();
}
