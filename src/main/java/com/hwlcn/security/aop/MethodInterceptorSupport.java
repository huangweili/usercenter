/**
 * 根据用户进行方法执行拦截，判断用户是否有该方法的执行权限
 */
package com.hwlcn.security.aop;

import com.hwlcn.security.SecurityUtils;
import com.hwlcn.security.subject.Subject;


public abstract class MethodInterceptorSupport implements MethodInterceptor {

    public MethodInterceptorSupport() {
    }

    protected Subject getSubject() {
        return SecurityUtils.getSubject();
    }
}
