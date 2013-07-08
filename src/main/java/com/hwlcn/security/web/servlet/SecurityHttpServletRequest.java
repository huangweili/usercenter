package com.hwlcn.security.web.servlet;


import com.hwlcn.security.SecurityUtils;
import com.hwlcn.security.session.Session;
import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.subject.support.DisabledSessionException;
import com.hwlcn.security.web.util.WebUtils;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpSession;
import java.security.Principal;

public class SecurityHttpServletRequest extends HttpServletRequestWrapper {


    public static final String COOKIE_SESSION_ID_SOURCE = "cookie";
    public static final String URL_SESSION_ID_SOURCE = "url";

    public static final String REFERENCED_SESSION_ID = SecurityHttpServletRequest.class.getName() + "_REQUESTED_SESSION_ID";
    public static final String REFERENCED_SESSION_ID_IS_VALID = SecurityHttpServletRequest.class.getName() + "_REQUESTED_SESSION_ID_VALID";
    public static final String REFERENCED_SESSION_IS_NEW = SecurityHttpServletRequest.class.getName() + "_REFERENCED_SESSION_IS_NEW";
    public static final String REFERENCED_SESSION_ID_SOURCE = SecurityHttpServletRequest.class.getName() + "REFERENCED_SESSION_ID_SOURCE";
    public static final String IDENTITY_REMOVED_KEY = SecurityHttpServletRequest.class.getName() + "_IDENTITY_REMOVED_KEY";


    protected ServletContext servletContext = null;

    protected HttpSession session = null;
    protected boolean httpSessions = true;

    public SecurityHttpServletRequest(HttpServletRequest wrapped, ServletContext servletContext, boolean httpSessions) {
        super(wrapped);
        this.servletContext = servletContext;
        this.httpSessions = httpSessions;
    }

    public boolean isHttpSessions() {
        return httpSessions;
    }

    public String getRemoteUser() {
        String remoteUser;
        Object scPrincipal = getSubjectPrincipal();
        if (scPrincipal != null) {
            if (scPrincipal instanceof String) {
                return (String) scPrincipal;
            } else if (scPrincipal instanceof Principal) {
                remoteUser = ((Principal) scPrincipal).getName();
            } else {
                remoteUser = scPrincipal.toString();
            }
        } else {
            remoteUser = super.getRemoteUser();
        }
        return remoteUser;
    }

    protected Subject getSubject() {
        return SecurityUtils.getSubject();
    }

    protected Object getSubjectPrincipal() {
        Object userPrincipal = null;
        Subject subject = getSubject();
        if (subject != null) {
            userPrincipal = subject.getPrincipal();
        }
        return userPrincipal;
    }

    public boolean isUserInRole(String s) {
        Subject subject = getSubject();
        boolean inRole = (subject != null && subject.hasRole(s));
        if (!inRole) {
            inRole = super.isUserInRole(s);
        }
        return inRole;
    }

    public Principal getUserPrincipal() {
        Principal userPrincipal;
        Object scPrincipal = getSubjectPrincipal();
        if (scPrincipal != null) {
            if (scPrincipal instanceof Principal) {
                userPrincipal = (Principal) scPrincipal;
            } else {
                userPrincipal = new ObjectPrincipal(scPrincipal);
            }
        } else {
            userPrincipal = super.getUserPrincipal();
        }
        return userPrincipal;
    }

    public String getRequestedSessionId() {
        String requestedSessionId = null;
        if (isHttpSessions()) {
            requestedSessionId = super.getRequestedSessionId();
        } else {
            Object sessionId = getAttribute(REFERENCED_SESSION_ID);
            if (sessionId != null) {
                requestedSessionId = sessionId.toString();
            }
        }

        return requestedSessionId;
    }

    public HttpSession getSession(boolean create) {

        HttpSession httpSession;

        if (isHttpSessions()) {
            httpSession = super.getSession(false);
            if (httpSession == null && create) {
                if (WebUtils._isSessionCreationEnabled(this)) {
                    httpSession = super.getSession(create);
                } else {
                    throw newNoSessionCreationException();
                }
            }
        } else {
            if (this.session == null) {

                boolean existing = getSubject().getSession(false) != null;

                Session session = getSubject().getSession(create);
                if (session != null) {
                    this.session = new SecurityHttpSession(session, this, this.servletContext);
                    if (!existing) {
                        setAttribute(REFERENCED_SESSION_IS_NEW, Boolean.TRUE);
                    }
                }
            }
            httpSession = this.session;
        }

        return httpSession;
    }


    private DisabledSessionException newNoSessionCreationException() {
        String msg = "Session creation has been disabled for the current request.  This exception indicates " +
                "that there is either a programming error (using a session when it should never be " +
                "used) or  configuration needs to be adjusted to allow Sessions to be created " +
                "for the current request.  See the " + DisabledSessionException.class.getName() + " JavaDoc " +
                "for more.";
        return new DisabledSessionException(msg);
    }

    public HttpSession getSession() {
        return getSession(true);
    }

    public boolean isRequestedSessionIdValid() {
        if (isHttpSessions()) {
            return super.isRequestedSessionIdValid();
        } else {
            Boolean value = (Boolean) getAttribute(REFERENCED_SESSION_ID_IS_VALID);
            return (value != null && value.equals(Boolean.TRUE));
        }
    }

    public boolean isRequestedSessionIdFromCookie() {
        if (isHttpSessions()) {
            return super.isRequestedSessionIdFromCookie();
        } else {
            String value = (String) getAttribute(REFERENCED_SESSION_ID_SOURCE);
            return value != null && value.equals(COOKIE_SESSION_ID_SOURCE);
        }
    }

    public boolean isRequestedSessionIdFromURL() {
        if (isHttpSessions()) {
            return super.isRequestedSessionIdFromURL();
        } else {
            String value = (String) getAttribute(REFERENCED_SESSION_ID_SOURCE);
            return value != null && value.equals(URL_SESSION_ID_SOURCE);
        }
    }

    public boolean isRequestedSessionIdFromUrl() {
        return isRequestedSessionIdFromURL();
    }

    private class ObjectPrincipal implements Principal {
        private Object object = null;

        public ObjectPrincipal(Object object) {
            this.object = object;
        }

        public Object getObject() {
            return object;
        }

        public String getName() {
            return getObject().toString();
        }

        public int hashCode() {
            return object.hashCode();
        }

        public boolean equals(Object o) {
            if (o instanceof ObjectPrincipal) {
                ObjectPrincipal op = (ObjectPrincipal) o;
                return getObject().equals(op.getObject());
            }
            return false;
        }

        public String toString() {
            return object.toString();
        }
    }
}
