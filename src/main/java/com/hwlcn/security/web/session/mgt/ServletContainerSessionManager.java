package com.hwlcn.security.web.session.mgt;


import com.hwlcn.security.authz.AuthorizationException;
import com.hwlcn.security.session.Session;
import com.hwlcn.security.session.SessionException;
import com.hwlcn.security.session.mgt.SessionContext;
import com.hwlcn.security.session.mgt.SessionKey;
import com.hwlcn.security.web.session.HttpServletSession;
import com.hwlcn.security.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;


public class ServletContainerSessionManager implements WebSessionManager {


    public ServletContainerSessionManager() {
    }

    public Session start(SessionContext context) throws AuthorizationException {
        return createSession(context);
    }

    public Session getSession(SessionKey key) throws SessionException {
        if (!WebUtils.isHttp(key)) {
            String msg = "SessionKey must be an HTTP compatible implementation.";
            throw new IllegalArgumentException(msg);
        }

        HttpServletRequest request = WebUtils.getHttpRequest(key);

        Session session = null;

        HttpSession httpSession = request.getSession(false);
        if (httpSession != null) {
            session = createSession(httpSession, request.getRemoteHost());
        }

        return session;
    }

    private String getHost(SessionContext context) {
        String host = context.getHost();
        if (host == null) {
            ServletRequest request = WebUtils.getRequest(context);
            if (request != null) {
                host = request.getRemoteHost();
            }
        }
        return host;

    }

    protected Session createSession(SessionContext sessionContext) throws AuthorizationException {
        if (!WebUtils.isHttp(sessionContext)) {
            String msg = "SessionContext must be an HTTP compatible implementation.";
            throw new IllegalArgumentException(msg);
        }

        HttpServletRequest request = WebUtils.getHttpRequest(sessionContext);

        HttpSession httpSession = request.getSession();

        String host = getHost(sessionContext);

        return createSession(httpSession, host);
    }

    protected Session createSession(HttpSession httpSession, String host) {
        return new HttpServletSession(httpSession, host);
    }

    public boolean isServletContainerSessions() {
        return true;
    }
}
