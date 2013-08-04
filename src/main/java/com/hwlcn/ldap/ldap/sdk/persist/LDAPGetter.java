package com.hwlcn.ldap.ldap.sdk.persist;



import java.lang.annotation.ElementType;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;



@Documented()
@Retention(RetentionPolicy.RUNTIME)
@Target(value={ElementType.METHOD})
public @interface LDAPGetter
{

  boolean inAdd() default true;


  boolean inModify() default true;




  boolean inRDN() default false;


  Class<? extends ObjectEncoder> encoderClass()
       default DefaultObjectEncoder.class;


  FilterUsage filterUsage() default FilterUsage.CONDITIONALLY_ALLOWED;




  String attribute() default "";


  String[] objectClass() default {};
}
