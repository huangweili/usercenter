package com.hwlcn.security.spring.security.interceptor;


import com.hwlcn.security.authz.annotation.*;
import com.hwlcn.security.mgt.SecurityManager;
import org.aopalliance.aop.Advice;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.support.StaticMethodMatcherPointcutAdvisor;
import org.springframework.core.annotation.AnnotationUtils;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;


@SuppressWarnings({"unchecked"})
public class AuthorizationAttributeSourceAdvisor extends StaticMethodMatcherPointcutAdvisor {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationAttributeSourceAdvisor.class);

    private static final Class<? extends Annotation>[] AUTHZ_ANNOTATION_CLASSES =
            new Class[] {
                    RequiresPermissions.class, RequiresRoles.class,
                    RequiresUser.class, RequiresGuest.class, RequiresAuthentication.class
            };

    protected SecurityManager securityManager = null;


    public AuthorizationAttributeSourceAdvisor() {
        Advice advice=new AopAllianceAnnotationsAuthorizingMethodInterceptor();
        setAdvice(advice);
    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    public void setSecurityManager(SecurityManager securityManager) {
        this.securityManager = securityManager;
    }


    public boolean matches(Method method, Class targetClass) {
        Method m = method;

        if ( isAuthzAnnotationPresent(m) ) {
            return true;
        }

        if ( targetClass != null) {
            try {
                m = targetClass.getMethod(m.getName(), m.getParameterTypes());
                if ( isAuthzAnnotationPresent(m) ) {
                    return true;
                }
            } catch (NoSuchMethodException ignored) {
                 log.error("no suchmethodexception {}",ignored);
            }
        }

        return false;
    }

    private boolean isAuthzAnnotationPresent(Method method) {
        for( Class<? extends Annotation> annClass : AUTHZ_ANNOTATION_CLASSES ) {
            Annotation a = AnnotationUtils.findAnnotation(method, annClass);
            if ( a != null ) {
                return true;
            }
        }
        return false;
    }

}
