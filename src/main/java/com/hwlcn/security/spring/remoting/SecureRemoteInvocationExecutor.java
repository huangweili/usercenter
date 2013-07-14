package com.hwlcn.security.spring.remoting;

import com.hwlcn.security.SecurityUtils;
import com.hwlcn.security.mgt.SecurityManager;
import com.hwlcn.security.subject.ExecutionException;
import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.subject.SubjectBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.remoting.support.DefaultRemoteInvocationExecutor;
import org.springframework.remoting.support.RemoteInvocation;

import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.Callable;


public class SecureRemoteInvocationExecutor extends DefaultRemoteInvocationExecutor {

    private static final Logger log = LoggerFactory.getLogger(SecureRemoteInvocationExecutor.class);

    private SecurityManager securityManager;


    public void setSecurityManager(SecurityManager securityManager) {
        this.securityManager = securityManager;
    }


    public Object invoke(final RemoteInvocation invocation, final Object targetObject)
            throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {

        try {
            SecurityManager securityManager =
                    this.securityManager != null ? this.securityManager : SecurityUtils.getSecurityManager();

            SubjectBuilder builder = new SubjectBuilder(securityManager);

            String host = (String) invocation.getAttribute(SecureRemoteInvocationFactory.HOST_KEY);
            if (host != null) {
                builder.host(host);
            }

            Serializable sessionId = invocation.getAttribute(SecureRemoteInvocationFactory.SESSION_ID_KEY);
            if (sessionId != null) {
                builder.sessionId(sessionId);
            } else {
                if (log.isTraceEnabled()) {
                    log.trace("RemoteInvocation did not contain a Security Session id attribute under " +
                            "key [" + SecureRemoteInvocationFactory.SESSION_ID_KEY + "].  A Subject based " +
                            "on an existing Session will not be available during the method invocatin.");
                }
            }

            Subject subject = builder.buildSubject();
            return subject.execute(new Callable() {
                public Object call() throws Exception {
                    return SecureRemoteInvocationExecutor.super.invoke(invocation, targetObject);
                }
            });
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof NoSuchMethodException) {
                throw (NoSuchMethodException) cause;
            } else if (cause instanceof IllegalAccessException) {
                throw (IllegalAccessException) cause;
            } else if (cause instanceof InvocationTargetException) {
                throw (InvocationTargetException) cause;
            } else {
                throw new InvocationTargetException(cause);
            }
        } catch (Throwable t) {
            throw new InvocationTargetException(t);
        }
    }
}
