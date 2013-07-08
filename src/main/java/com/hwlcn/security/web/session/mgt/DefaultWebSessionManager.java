package com.hwlcn.security.web.session.mgt;

import com.hwlcn.security.session.ExpiredSessionException;
import com.hwlcn.security.session.InvalidSessionException;
import com.hwlcn.security.session.Session;
import com.hwlcn.security.session.mgt.DefaultSessionManager;
import com.hwlcn.security.session.mgt.DelegatingSession;
import com.hwlcn.security.session.mgt.SessionContext;
import com.hwlcn.security.session.mgt.SessionKey;
import com.hwlcn.security.web.servlet.Cookie;
import com.hwlcn.security.web.servlet.SecurityHttpServletRequest;
import com.hwlcn.security.web.servlet.SecurityHttpSession;
import com.hwlcn.security.web.servlet.SimpleCookie;
import com.hwlcn.security.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;


public class DefaultWebSessionManager extends DefaultSessionManager implements WebSessionManager {

    private static final Logger log = LoggerFactory.getLogger(DefaultWebSessionManager.class);

    private Cookie sessionIdCookie;
    private boolean sessionIdCookieEnabled;

    public DefaultWebSessionManager() {
        Cookie cookie = new SimpleCookie(SecurityHttpSession.DEFAULT_SESSION_ID_NAME);
        cookie.setHttpOnly(true);
        this.sessionIdCookie = cookie;
        this.sessionIdCookieEnabled = true;
    }

    public Cookie getSessionIdCookie() {
        return sessionIdCookie;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public void setSessionIdCookie(Cookie sessionIdCookie) {
        this.sessionIdCookie = sessionIdCookie;
    }

    public boolean isSessionIdCookieEnabled() {
        return sessionIdCookieEnabled;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public void setSessionIdCookieEnabled(boolean sessionIdCookieEnabled) {
        this.sessionIdCookieEnabled = sessionIdCookieEnabled;
    }

    private void storeSessionId(Serializable currentId, HttpServletRequest request, HttpServletResponse response) {
        if (currentId == null) {
            String msg = "sessionId cannot be null when persisting for subsequent requests.";
            throw new IllegalArgumentException(msg);
        }
        Cookie template = getSessionIdCookie();
        Cookie cookie = new SimpleCookie(template);
        String idString = currentId.toString();
        cookie.setValue(idString);
        cookie.saveTo(request, response);
        if (log.isTraceEnabled()) {
            log.trace("Set session ID cookie for session with id {}", idString);
        }
    }

    private void removeSessionIdCookie(HttpServletRequest request, HttpServletResponse response) {
        getSessionIdCookie().removeFrom(request, response);
    }

    private String getSessionIdCookieValue(ServletRequest request, ServletResponse response) {
        if (!isSessionIdCookieEnabled()) {
            if (log.isDebugEnabled()) {
                log.debug("Session ID cookie is disabled - session id will not be acquired from a request cookie.");
            }
            return null;
        }
        if (!(request instanceof HttpServletRequest)) {
            if (log.isDebugEnabled()) {
                log.debug("Current request is not an HttpServletRequest - cannot get session ID cookie.  Returning null.");
            }
            return null;
        }
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        return getSessionIdCookie().readValue(httpRequest, WebUtils.toHttp(response));
    }

    private Serializable getReferencedSessionId(ServletRequest request, ServletResponse response) {

        String id = getSessionIdCookieValue(request, response);
        if (id != null) {
            request.setAttribute(SecurityHttpServletRequest.REFERENCED_SESSION_ID_SOURCE,
                    SecurityHttpServletRequest.COOKIE_SESSION_ID_SOURCE);
        } else {
            id = getUriPathSegmentParamValue(request, SecurityHttpSession.DEFAULT_SESSION_ID_NAME);

            if (id == null) {
                String name = getSessionIdName();
                id = request.getParameter(name);
                if (id == null) {
                    id = request.getParameter(name.toLowerCase());
                }
            }
            if (id != null) {
                request.setAttribute(SecurityHttpServletRequest.REFERENCED_SESSION_ID_SOURCE,
                        SecurityHttpServletRequest.URL_SESSION_ID_SOURCE);
            }
        }
        if (id != null) {
            request.setAttribute(SecurityHttpServletRequest.REFERENCED_SESSION_ID, id);
            request.setAttribute(SecurityHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE);
        }
        return id;
    }

    private String getUriPathSegmentParamValue(ServletRequest servletRequest, String paramName) {

        if (!(servletRequest instanceof HttpServletRequest)) {
            return null;
        }
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        String uri = request.getRequestURI();
        if (uri == null) {
            return null;
        }

        int queryStartIndex = uri.indexOf('?');
        if (queryStartIndex >= 0) {
            uri = uri.substring(0, queryStartIndex);
        }

        int index = uri.indexOf(';');
        if (index < 0) {
            return null;
        }

        final String TOKEN = paramName + "=";

        uri = uri.substring(index + 1);
        index = uri.lastIndexOf(TOKEN);
        if (index < 0) {

            return null;
        }

        uri = uri.substring(index + TOKEN.length());

        index = uri.indexOf(';');
        if (index >= 0) {
            uri = uri.substring(0, index);
        }

        return uri;
    }

    private String getSessionIdName() {
        String name = this.sessionIdCookie != null ? this.sessionIdCookie.getName() : null;
        if (name == null) {
            name = SecurityHttpSession.DEFAULT_SESSION_ID_NAME;
        }
        return name;
    }

    protected Session createExposedSession(Session session, SessionContext context) {
        if (!WebUtils.isWeb(context)) {
            return super.createExposedSession(session, context);
        }
        ServletRequest request = WebUtils.getRequest(context);
        ServletResponse response = WebUtils.getResponse(context);
        SessionKey key = new WebSessionKey(session.getId(), request, response);
        return new DelegatingSession(this, key);
    }

    protected Session createExposedSession(Session session, SessionKey key) {
        if (!WebUtils.isWeb(key)) {
            return super.createExposedSession(session, key);
        }

        ServletRequest request = WebUtils.getRequest(key);
        ServletResponse response = WebUtils.getResponse(key);
        SessionKey sessionKey = new WebSessionKey(session.getId(), request, response);
        return new DelegatingSession(this, sessionKey);
    }

    @Override
    protected void onStart(Session session, SessionContext context) {
        super.onStart(session, context);

        if (!WebUtils.isHttp(context)) {
            log.debug("SessionContext argument is not HTTP compatible or does not have an HTTP request/response " +
                    "pair. No session ID cookie will be set.");
            return;

        }
        HttpServletRequest request = WebUtils.getHttpRequest(context);
        HttpServletResponse response = WebUtils.getHttpResponse(context);

        if (isSessionIdCookieEnabled()) {
            Serializable sessionId = session.getId();
            storeSessionId(sessionId, request, response);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Session ID cookie is disabled.  No cookie has been set for new session with id {}", session.getId());
            }
        }

        request.removeAttribute(SecurityHttpServletRequest.REFERENCED_SESSION_ID_SOURCE);
        request.setAttribute(SecurityHttpServletRequest.REFERENCED_SESSION_IS_NEW, Boolean.TRUE);
    }

    @Override
    public Serializable getSessionId(SessionKey key) {
        Serializable id = super.getSessionId(key);
        if (id == null && WebUtils.isWeb(key)) {
            ServletRequest request = WebUtils.getRequest(key);
            ServletResponse response = WebUtils.getResponse(key);
            id = getSessionId(request, response);
        }
        return id;
    }

    protected Serializable getSessionId(ServletRequest request, ServletResponse response) {
        return getReferencedSessionId(request, response);
    }

    @Override
    protected void onExpiration(Session s, ExpiredSessionException ese, SessionKey key) {
        super.onExpiration(s, ese, key);
        onInvalidation(key);
    }

    @Override
    protected void onInvalidation(Session session, InvalidSessionException ise, SessionKey key) {
        super.onInvalidation(session, ise, key);
        onInvalidation(key);
    }

    private void onInvalidation(SessionKey key) {
        ServletRequest request = WebUtils.getRequest(key);
        if (request != null) {
            request.removeAttribute(SecurityHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID);
        }
        if (WebUtils.isHttp(key)) {
            if (log.isDebugEnabled()) {
                log.debug("Referenced session was invalid.  Removing session ID cookie.");
            }
            removeSessionIdCookie(WebUtils.getHttpRequest(key), WebUtils.getHttpResponse(key));
        } else {
            if (log.isDebugEnabled()) {
                log.debug("SessionKey argument is not HTTP compatible or does not have an HTTP request/response " +
                        "pair. Session ID cookie will not be removed due to invalidated session.");
            }
        }
    }

    @Override
    protected void onStop(Session session, SessionKey key) {
        super.onStop(session, key);
        if (WebUtils.isHttp(key)) {
            HttpServletRequest request = WebUtils.getHttpRequest(key);
            HttpServletResponse response = WebUtils.getHttpResponse(key);
            if (log.isDebugEnabled()) {
                log.debug("Session has been stopped (subject logout or explicit stop).  Removing session ID cookie.");
            }
            removeSessionIdCookie(request, response);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("SessionKey argument is not HTTP compatible or does not have an HTTP request/response " +
                        "pair. Session ID cookie will not be removed due to stopped session.");
            }
        }
    }

    public boolean isServletContainerSessions() {
        return false;
    }
}
