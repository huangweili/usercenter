package com.hwlcn.security.subject.support;

import com.hwlcn.security.SecurityUtils;
import com.hwlcn.security.UnavailableSecurityManagerException;
import com.hwlcn.security.authc.AuthenticationInfo;
import com.hwlcn.security.authc.AuthenticationToken;
import com.hwlcn.security.authc.HostAuthenticationToken;
import com.hwlcn.security.mgt.SecurityManager;
import com.hwlcn.security.session.Session;
import com.hwlcn.security.subject.PrincipalCollection;
import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.subject.SubjectContext;
import com.hwlcn.security.util.CollectionUtils;
import com.hwlcn.security.util.MapContext;
import com.hwlcn.security.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;

public class DefaultSubjectContext extends MapContext implements SubjectContext {

    private static final String SECURITY_MANAGER = DefaultSubjectContext.class.getName() + ".SECURITY_MANAGER";

    private static final String SESSION_ID = DefaultSubjectContext.class.getName() + ".SESSION_ID";

    private static final String AUTHENTICATION_TOKEN = DefaultSubjectContext.class.getName() + ".AUTHENTICATION_TOKEN";

    private static final String AUTHENTICATION_INFO = DefaultSubjectContext.class.getName() + ".AUTHENTICATION_INFO";

    private static final String SUBJECT = DefaultSubjectContext.class.getName() + ".SUBJECT";

    private static final String PRINCIPALS = DefaultSubjectContext.class.getName() + ".PRINCIPALS";

    private static final String SESSION = DefaultSubjectContext.class.getName() + ".SESSION";

    private static final String AUTHENTICATED = DefaultSubjectContext.class.getName() + ".AUTHENTICATED";

    private static final String HOST = DefaultSubjectContext.class.getName() + ".HOST";

    public static final String SESSION_CREATION_ENABLED = DefaultSubjectContext.class.getName() + ".SESSION_CREATION_ENABLED";

    public static final String PRINCIPALS_SESSION_KEY = DefaultSubjectContext.class.getName() + "_PRINCIPALS_SESSION_KEY";

    public static final String AUTHENTICATED_SESSION_KEY = DefaultSubjectContext.class.getName() + "_AUTHENTICATED_SESSION_KEY";

    private static final transient Logger log = LoggerFactory.getLogger(DefaultSubjectContext.class);

    public DefaultSubjectContext() {
        super();
    }

    public DefaultSubjectContext(SubjectContext ctx) {
        super(ctx);
    }

    public SecurityManager getSecurityManager() {
        return getTypedValue(SECURITY_MANAGER, SecurityManager.class);
    }

    public void setSecurityManager(SecurityManager securityManager) {
        nullSafePut(SECURITY_MANAGER, securityManager);
    }

    public SecurityManager resolveSecurityManager() {
        SecurityManager securityManager = getSecurityManager();
        if (securityManager == null) {
            if (log.isDebugEnabled()) {
                log.debug("No SecurityManager available in subject context map.  " +
                        "Falling back to SecurityUtils.getSecurityManager() lookup.");
            }
            try {
                securityManager = SecurityUtils.getSecurityManager();
            } catch (UnavailableSecurityManagerException e) {
                if (log.isDebugEnabled()) {
                    log.debug("No SecurityManager available via SecurityUtils.  Heuristics exhausted.", e);
                }
            }
        }
        return securityManager;
    }

    public Serializable getSessionId() {
        return getTypedValue(SESSION_ID, Serializable.class);
    }

    public void setSessionId(Serializable sessionId) {
        nullSafePut(SESSION_ID, sessionId);
    }

    public Subject getSubject() {
        return getTypedValue(SUBJECT, Subject.class);
    }

    public void setSubject(Subject subject) {
        nullSafePut(SUBJECT, subject);
    }

    public PrincipalCollection getPrincipals() {
        return getTypedValue(PRINCIPALS, PrincipalCollection.class);
    }

    public void setPrincipals(PrincipalCollection principals) {
        if (!CollectionUtils.isEmpty(principals)) {
            put(PRINCIPALS, principals);
        }
    }

    public PrincipalCollection resolvePrincipals() {
        PrincipalCollection principals = getPrincipals();

        if (CollectionUtils.isEmpty(principals)) {
            AuthenticationInfo info = getAuthenticationInfo();
            if (info != null) {
                principals = info.getPrincipals();
            }
        }

        if (CollectionUtils.isEmpty(principals)) {
            Subject subject = getSubject();
            if (subject != null) {
                principals = subject.getPrincipals();
            }
        }

        if (CollectionUtils.isEmpty(principals)) {
            Session session = resolveSession();
            if (session != null) {
                principals = (PrincipalCollection) session.getAttribute(PRINCIPALS_SESSION_KEY);
            }
        }

        return principals;
    }


    public Session getSession() {
        return getTypedValue(SESSION, Session.class);
    }

    public void setSession(Session session) {
        nullSafePut(SESSION, session);
    }

    public Session resolveSession() {
        Session session = getSession();
        if (session == null) {
            Subject existingSubject = getSubject();
            if (existingSubject != null) {
                session = existingSubject.getSession(false);
            }
        }
        return session;
    }

    public boolean isSessionCreationEnabled() {
        Boolean val = getTypedValue(SESSION_CREATION_ENABLED, Boolean.class);
        return val == null || val;
    }

    public void setSessionCreationEnabled(boolean enabled) {
        nullSafePut(SESSION_CREATION_ENABLED, enabled);
    }

    public boolean isAuthenticated() {
        Boolean authc = getTypedValue(AUTHENTICATED, Boolean.class);
        return authc != null && authc;
    }

    public void setAuthenticated(boolean authc) {
        put(AUTHENTICATED, authc);
    }

    public boolean resolveAuthenticated() {
        Boolean authc = getTypedValue(AUTHENTICATED, Boolean.class);
        if (authc == null) {
            AuthenticationInfo info = getAuthenticationInfo();
            authc = info != null;
        }
        if (!authc) {
            Session session = resolveSession();
            if (session != null) {
                Boolean sessionAuthc = (Boolean) session.getAttribute(AUTHENTICATED_SESSION_KEY);
                authc = sessionAuthc != null && sessionAuthc;
            }
        }

        return authc;
    }

    public AuthenticationInfo getAuthenticationInfo() {
        return getTypedValue(AUTHENTICATION_INFO, AuthenticationInfo.class);
    }

    public void setAuthenticationInfo(AuthenticationInfo info) {
        nullSafePut(AUTHENTICATION_INFO, info);
    }

    public AuthenticationToken getAuthenticationToken() {
        return getTypedValue(AUTHENTICATION_TOKEN, AuthenticationToken.class);
    }

    public void setAuthenticationToken(AuthenticationToken token) {
        nullSafePut(AUTHENTICATION_TOKEN, token);
    }

    public String getHost() {
        return getTypedValue(HOST, String.class);
    }

    public void setHost(String host) {
        if (StringUtils.hasText(host)) {
            put(HOST, host);
        }
    }

    public String resolveHost() {
        String host = getHost();

        if (host == null) {
            AuthenticationToken token = getAuthenticationToken();
            if (token instanceof HostAuthenticationToken) {
                host = ((HostAuthenticationToken) token).getHost();
            }
        }

        if (host == null) {
            Session session = resolveSession();
            if (session != null) {
                host = session.getHost();
            }
        }

        return host;
    }
}
