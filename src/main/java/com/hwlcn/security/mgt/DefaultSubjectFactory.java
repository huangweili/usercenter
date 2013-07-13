package com.hwlcn.security.mgt;

import com.hwlcn.security.session.Session;
import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.subject.support.DelegatingSubject;
import com.hwlcn.security.subject.PrincipalCollection;
import com.hwlcn.security.subject.SubjectContext;


public class DefaultSubjectFactory implements SubjectFactory {

    public DefaultSubjectFactory() {
    }

    public Subject createSubject(SubjectContext context) {
        SecurityManager securityManager = context.resolveSecurityManager();
        Session session = context.resolveSession();
        boolean sessionCreationEnabled = context.isSessionCreationEnabled();
        PrincipalCollection principals = context.resolvePrincipals();
        boolean authenticated = context.resolveAuthenticated();
        String host = context.resolveHost();

        return new DelegatingSubject(principals, authenticated, host, session, sessionCreationEnabled, securityManager);
    }


}
