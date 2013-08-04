package com.hwlcn.ldap.ldap.sdk.persist;



import java.lang.annotation.ElementType;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Documented()
@Retention(RetentionPolicy.RUNTIME)
@Target(value={ElementType.TYPE})
public @interface LDAPObject
{

  boolean requestAllAttributes() default false;

  String defaultParentDN() default "";


  String postDecodeMethod() default "";




  String postEncodeMethod() default "";



  String structuralClass() default "";


  String[] auxiliaryClass() default {};


  String[] superiorClass() default {};
}
