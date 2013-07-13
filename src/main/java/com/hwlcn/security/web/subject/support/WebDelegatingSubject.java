package com.hwlcn.security.web.subject.support;

import com.hwlcn.security.mgt.SecurityManager;
import com.hwlcn.security.session.Session;
import com.hwlcn.security.session.mgt.SessionContext;
import com.hwlcn.security.subject.PrincipalCollection;
import com.hwlcn.security.subject.support.DelegatingSubject;
import com.hwlcn.security.util.StringUtils;
import com.hwlcn.security.web.session.mgt.DefaultWebSessionContext;
import com.hwlcn.security.web.session.mgt.WebSessionContext;
import com.hwlcn.security.web.subject.WebSubject;
import com.hwlcn.security.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


public class WebDelegatingSubject extends DelegatingSubject implements WebSubject {

    private static final long serialVersionUID = -1655724323350159250L;

    private final ServletRequest servletRequest;
    private final ServletResponse servletResponse;

    public WebDelegatingSubject(PrincipalCollection principals, boolean authenticated,
                                String host, Session session,
                                ServletRequest request, ServletResponse response,
                                SecurityManager securityManager) {
        this(principals, authenticated, host, session, true, request, response, securityManager);
    }


    public WebDelegatingSubject(PrincipalCollection principals, boolean authenticated,
                                String host, Session session, boolean sessionEnabled,
                                ServletRequest request, ServletResponse response,
                                SecurityManager securityManager) {
        super(principals, authenticated, host, session, sessionEnabled, securityManager);
        this.servletRequest = request;
        this.servletResponse = response;
    }

    public ServletRequest getServletRequest() {
        return servletRequest;
    }

    public ServletResponse getServletResponse() {
        return servletResponse;
    }


    @Override
    protected boolean isSessionCreationEnabled() {
        boolean enabled = super.isSessionCreationEnabled();
        return enabled && WebUtils._isSessionCreationEnabled(this);
    }

    @Override
    protected SessionContext createSessionContext() {
        WebSessionContext wsc = new DefaultWebSessionContext();
        String host = getHost();
        if (StringUtils.hasText(host)) {
            wsc.setHost(host);
        }
        wsc.setServletRequest(this.servletRequest);
        wsc.setServletResponse(this.servletResponse);
        return wsc;
    }
}
