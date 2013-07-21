package com.hwlcn.db;

import org.springframework.stereotype.Component;

import java.lang.annotation.*;

/**
 * User: HuangWeili
 * Date: 13-7-20
 * Time: 下午5:10
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
@Component
public @interface DBMapper {
    String value() default "";
}
