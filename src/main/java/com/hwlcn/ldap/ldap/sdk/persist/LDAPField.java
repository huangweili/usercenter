
package com.hwlcn.ldap.ldap.sdk.persist;



import java.lang.annotation.ElementType;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;


@Documented()
@Retention(RetentionPolicy.RUNTIME)
@Target(value={ElementType.FIELD})
public @interface LDAPField
{

  boolean failOnInvalidValue() default true;




  boolean failOnTooManyValues() default true;



  boolean inAdd() default true;


  boolean inModify() default true;



  boolean inRDN() default false;


  boolean lazilyLoad() default false;



  boolean requiredForDecode() default false;


  boolean requiredForEncode() default false;



  Class<? extends ObjectEncoder> encoderClass()
       default DefaultObjectEncoder.class;


  FilterUsage filterUsage() default FilterUsage.CONDITIONALLY_ALLOWED;



  String attribute() default "";



  String[] defaultDecodeValue() default {};



  String[] defaultEncodeValue() default {};


  String[] objectClass() default {};
}
