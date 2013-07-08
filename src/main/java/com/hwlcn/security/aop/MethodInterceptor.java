/**
 * 方法中断拦截
 */
package com.hwlcn.security.aop;

public interface MethodInterceptor {


    Object invoke(MethodInvocation methodInvocation) throws Throwable;

}
