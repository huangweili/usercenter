package com.hwlcn.security.subject;

import com.hwlcn.security.SecurityUtils;
import com.hwlcn.security.session.Session;
import com.hwlcn.security.subject.support.DefaultSubjectContext;
import com.hwlcn.security.util.CollectionUtils;
import com.hwlcn.security.util.StringUtils;

import java.io.Serializable;

/**
 * User: HuangWeili
 * Date: 13-7-8
 * Time: 下午10:17
 */
public class SubjectBuilder {
    private final SubjectContext subjectContext;

    private final com.hwlcn.security.mgt.SecurityManager securityManager;

    public SubjectBuilder() {
        this(SecurityUtils.getSecurityManager());
    }

    public SubjectBuilder(com.hwlcn.security.mgt.SecurityManager securityManager) {
        if (securityManager == null) {
            throw new NullPointerException("SecurityManager method argument cannot be null.");
        }
        this.securityManager = securityManager;
        this.subjectContext = newSubjectContextInstance();
        if (this.subjectContext == null) {
            throw new IllegalStateException("Subject instance returned from 'newSubjectContextInstance' " +
                    "cannot be null.");
        }
        this.subjectContext.setSecurityManager(securityManager);
    }

    protected SubjectContext newSubjectContextInstance() {
        return new DefaultSubjectContext();
    }

    protected SubjectContext getSubjectContext() {
        return this.subjectContext;
    }

    public SubjectBuilder sessionId(Serializable sessionId) {
        if (sessionId != null) {
            this.subjectContext.setSessionId(sessionId);
        }
        return this;
    }

    public SubjectBuilder host(String host) {
        if (StringUtils.hasText(host)) {
            this.subjectContext.setHost(host);
        }
        return this;
    }

    public SubjectBuilder session(Session session) {
        if (session != null) {
            this.subjectContext.setSession(session);
        }
        return this;
    }


    public SubjectBuilder principals(PrincipalCollection principals) {
        if (!CollectionUtils.isEmpty(principals)) {
            this.subjectContext.setPrincipals(principals);
        }
        return this;
    }


    public SubjectBuilder sessionCreationEnabled(boolean enabled) {
        this.subjectContext.setSessionCreationEnabled(enabled);
        return this;
    }


    public SubjectBuilder authenticated(boolean authenticated) {
        this.subjectContext.setAuthenticated(authenticated);
        return this;
    }


    public SubjectBuilder contextAttribute(String attributeKey, Object attributeValue) {
        if (attributeKey == null) {
            String msg = "Subject context map key cannot be null.";
            throw new IllegalArgumentException(msg);
        }
        if (attributeValue == null) {
            this.subjectContext.remove(attributeKey);
        } else {
            this.subjectContext.put(attributeKey, attributeValue);
        }
        return this;
    }


    public Subject buildSubject() {
        return this.securityManager.createSubject(this.subjectContext);
    }
}
