package com.hwlcn.security.web.mgt;

import com.hwlcn.security.mgt.DefaultSubjectFactory;
import com.hwlcn.security.mgt.SecurityManager;
import com.hwlcn.security.session.Session;
import com.hwlcn.security.subject.PrincipalCollection;
import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.subject.SubjectContext;
import com.hwlcn.security.web.subject.WebSubjectContext;
import com.hwlcn.security.web.subject.support.WebDelegatingSubject;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class DefaultWebSubjectFactory extends DefaultSubjectFactory {

    public DefaultWebSubjectFactory() {
        super();
    }

    public Subject createSubject(SubjectContext context) {
        if (!(context instanceof WebSubjectContext)) {
            return super.createSubject(context);
        }
        WebSubjectContext wsc = (WebSubjectContext) context;
        SecurityManager securityManager = wsc.resolveSecurityManager();
        Session session = wsc.resolveSession();
        boolean sessionEnabled = wsc.isSessionCreationEnabled();
        PrincipalCollection principals = wsc.resolvePrincipals();
        boolean authenticated = wsc.resolveAuthenticated();
        String host = wsc.resolveHost();
        ServletRequest request = wsc.resolveServletRequest();
        ServletResponse response = wsc.resolveServletResponse();

        return new WebDelegatingSubject(principals, authenticated, host, session, sessionEnabled,
                request, response, securityManager);
    }
}
