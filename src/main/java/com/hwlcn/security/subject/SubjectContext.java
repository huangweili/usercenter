package com.hwlcn.security.subject;

import com.hwlcn.security.authc.AuthenticationInfo;
import com.hwlcn.security.authc.AuthenticationToken;
import com.hwlcn.security.mgt.SecurityManager;
import com.hwlcn.security.session.Session;

import java.io.Serializable;
import java.util.Map;

public interface SubjectContext extends Map<String, Object> {

    com.hwlcn.security.mgt.SecurityManager getSecurityManager();

    void setSecurityManager(SecurityManager securityManager);

    SecurityManager resolveSecurityManager();

    Serializable getSessionId();

    void setSessionId(Serializable sessionId);

    Subject getSubject();

    void setSubject(Subject subject);

    PrincipalCollection getPrincipals();

    PrincipalCollection resolvePrincipals();

    void setPrincipals(PrincipalCollection principals);

    Session getSession();

    void setSession(Session session);

    Session resolveSession();

    boolean isAuthenticated();

    void setAuthenticated(boolean authc);

    boolean isSessionCreationEnabled();

    void setSessionCreationEnabled(boolean enabled);

    boolean resolveAuthenticated();

    AuthenticationInfo getAuthenticationInfo();

    void setAuthenticationInfo(AuthenticationInfo info);

    AuthenticationToken getAuthenticationToken();

    void setAuthenticationToken(AuthenticationToken token);

    String getHost();

    void setHost(String host);

    String resolveHost();
}
