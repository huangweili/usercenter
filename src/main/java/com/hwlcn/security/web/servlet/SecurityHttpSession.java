package com.hwlcn.security.web.servlet;

import com.hwlcn.security.session.InvalidSessionException;
import com.hwlcn.security.session.Session;
import com.hwlcn.security.web.session.HttpServletSession;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionBindingEvent;
import javax.servlet.http.HttpSessionBindingListener;
import java.util.*;


public class SecurityHttpSession implements HttpSession {

    public static final String DEFAULT_SESSION_ID_NAME = "JSESSIONID";

    private static final Enumeration EMPTY_ENUMERATION = new Enumeration() {
        public boolean hasMoreElements() {
            return false;
        }

        public Object nextElement() {
            return null;
        }
    };

    @SuppressWarnings({"deprecation"})
    private static final javax.servlet.http.HttpSessionContext HTTP_SESSION_CONTEXT =
            new javax.servlet.http.HttpSessionContext() {
                public HttpSession getSession(String s) {
                    return null;
                }

                public Enumeration getIds() {
                    return EMPTY_ENUMERATION;
                }
            };

    protected ServletContext servletContext = null;
    protected HttpServletRequest currentRequest = null;
    protected Session session = null;

    public SecurityHttpSession(Session session, HttpServletRequest currentRequest, ServletContext servletContext) {
        if (session instanceof HttpServletSession) {
            String msg = "Session constructor argument cannot be an instance of HttpServletSession.  This is enforced to " +
                    "prevent circular dependencies and infinite loops.";
            throw new IllegalArgumentException(msg);
        }
        this.session = session;
        this.currentRequest = currentRequest;
        this.servletContext = servletContext;
    }

    public Session getSession() {
        return this.session;
    }

    public long getCreationTime() {
        try {
            return getSession().getStartTimestamp().getTime();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public String getId() {
        return getSession().getId().toString();
    }

    public long getLastAccessedTime() {
        return getSession().getLastAccessTime().getTime();
    }

    public ServletContext getServletContext() {
        return this.servletContext;
    }

    public void setMaxInactiveInterval(int i) {
        try {
            getSession().setTimeout(i * 1000);
        } catch (InvalidSessionException e) {
            throw new IllegalStateException(e);
        }
    }

    public int getMaxInactiveInterval() {
        try {
            return (new Long(getSession().getTimeout() / 1000)).intValue();
        } catch (InvalidSessionException e) {
            throw new IllegalStateException(e);
        }
    }

    @SuppressWarnings({"deprecation"})
    public javax.servlet.http.HttpSessionContext getSessionContext() {
        return HTTP_SESSION_CONTEXT;
    }

    public Object getAttribute(String s) {
        try {
            return getSession().getAttribute(s);
        } catch (InvalidSessionException e) {
            throw new IllegalStateException(e);
        }
    }

    public Object getValue(String s) {
        return getAttribute(s);
    }

    @SuppressWarnings({"unchecked"})
    protected Set<String> getKeyNames() {
        Collection<Object> keySet;
        try {
            keySet = getSession().getAttributeKeys();
        } catch (InvalidSessionException e) {
            throw new IllegalStateException(e);
        }
        Set<String> keyNames;
        if (keySet != null && !keySet.isEmpty()) {
            keyNames = new HashSet<String>(keySet.size());
            for (Object o : keySet) {
                keyNames.add(o.toString());
            }
        } else {
            keyNames = Collections.EMPTY_SET;
        }
        return keyNames;
    }

    public Enumeration getAttributeNames() {
        Set<String> keyNames = getKeyNames();
        final Iterator iterator = keyNames.iterator();
        return new Enumeration() {
            public boolean hasMoreElements() {
                return iterator.hasNext();
            }

            public Object nextElement() {
                return iterator.next();
            }
        };
    }

    public String[] getValueNames() {
        Set<String> keyNames = getKeyNames();
        String[] array = new String[keyNames.size()];
        if (keyNames.size() > 0) {
            array = keyNames.toArray(array);
        }
        return array;
    }

    protected void afterBound(String s, Object o) {
        if (o instanceof HttpSessionBindingListener) {
            HttpSessionBindingListener listener = (HttpSessionBindingListener) o;
            HttpSessionBindingEvent event = new HttpSessionBindingEvent(this, s, o);
            listener.valueBound(event);
        }
    }

    protected void afterUnbound(String s, Object o) {
        if (o instanceof HttpSessionBindingListener) {
            HttpSessionBindingListener listener = (HttpSessionBindingListener) o;
            HttpSessionBindingEvent event = new HttpSessionBindingEvent(this, s, o);
            listener.valueUnbound(event);
        }
    }

    public void setAttribute(String s, Object o) {
        try {
            getSession().setAttribute(s, o);
            afterBound(s, o);
        } catch (InvalidSessionException e) {

            try {
                afterUnbound(s, o);
            } finally {

                throw new IllegalStateException(e);
            }
        }
    }

    public void putValue(String s, Object o) {
        setAttribute(s, o);
    }

    public void removeAttribute(String s) {
        try {
            Object attribute = getSession().removeAttribute(s);
            afterUnbound(s, attribute);
        } catch (InvalidSessionException e) {
            throw new IllegalStateException(e);
        }
    }

    public void removeValue(String s) {
        removeAttribute(s);
    }

    public void invalidate() {
        try {
            getSession().stop();
        } catch (InvalidSessionException e) {
            throw new IllegalStateException(e);
        }
    }

    public boolean isNew() {
        Boolean value = (Boolean) currentRequest.getAttribute(SecurityHttpServletRequest.REFERENCED_SESSION_IS_NEW);
        return value != null && value.equals(Boolean.TRUE);
    }
}
