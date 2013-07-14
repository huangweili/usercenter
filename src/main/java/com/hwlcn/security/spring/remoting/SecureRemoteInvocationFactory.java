package com.hwlcn.security.spring.remoting;

import com.hwlcn.security.SecurityUtils;
import com.hwlcn.security.session.Session;
import com.hwlcn.security.session.mgt.NativeSessionManager;
import com.hwlcn.security.session.mgt.SessionKey;
import com.hwlcn.security.session.mgt.SessionManager;
import com.hwlcn.security.subject.Subject;
import org.aopalliance.intercept.MethodInvocation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.remoting.support.DefaultRemoteInvocationFactory;
import org.springframework.remoting.support.RemoteInvocation;

import java.io.Serializable;


public class SecureRemoteInvocationFactory extends DefaultRemoteInvocationFactory {

    private static final Logger log = LoggerFactory.getLogger(SecureRemoteInvocationFactory.class);

    public static final String SESSION_ID_KEY = SecureRemoteInvocationFactory.class.getName() + ".SESSION_ID_KEY";
    public static final String HOST_KEY = SecureRemoteInvocationFactory.class.getName() + ".HOST_KEY";

    private static final String SESSION_ID_SYSTEM_PROPERTY_NAME = "security.session.id";

    private String sessionId;

    public SecureRemoteInvocationFactory() {
    }

    public SecureRemoteInvocationFactory(String sessionId) {
        this();
        this.sessionId = sessionId;
    }


    public RemoteInvocation createRemoteInvocation(MethodInvocation mi) {

        Serializable sessionId = null;
        String host = null;
        boolean sessionManagerMethodInvocation = false;

        Class miDeclaringClass = mi.getMethod().getDeclaringClass();
        if (SessionManager.class.equals(miDeclaringClass) || NativeSessionManager.class.equals(miDeclaringClass)) {
            sessionManagerMethodInvocation = true;
            if (!mi.getMethod().getName().equals("start")) {
                SessionKey key = (SessionKey) mi.getArguments()[0];
                sessionId = key.getSessionId();
            }
        }

        if (sessionId == null) sessionId = this.sessionId;

        if (sessionId == null) {
            try {
                SecurityUtils.getSecurityManager();
                if (!sessionManagerMethodInvocation) {
                    Subject subject = SecurityUtils.getSubject();
                    Session session = subject.getSession(false);
                    if (session != null) {
                        sessionId = session.getId();
                        host = session.getHost();
                    }
                }
            }
            catch (Exception e) {
                log.error("No security manager set. Trying next to get session id from system property");
            }
        }
        if (sessionId == null) {
            if (log.isTraceEnabled()) {
                log.trace("No Session found for the currently executing subject via subject.getSession(false).  " +
                        "Attempting to revert back to the 'security.session.id' system property...");
            }
            sessionId = System.getProperty(SESSION_ID_SYSTEM_PROPERTY_NAME);
            if (sessionId == null && log.isTraceEnabled()) {
                log.trace("No 'security.session.id' system property found.  Heuristics have been exhausted; " +
                        "RemoteInvocation will not contain a sessionId.");
            }
        }

        RemoteInvocation ri = new RemoteInvocation(mi);
        if (sessionId != null) {
            ri.addAttribute(SESSION_ID_KEY, sessionId);
        }
        if (host != null) {
            ri.addAttribute(HOST_KEY, host);
        }

        return ri;
    }
}
