package com.hwlcn.security.session;

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;

public class ProxiedSession implements Session {

    protected final Session delegate;

    public ProxiedSession(Session target) {
        if (target == null) {
            throw new IllegalArgumentException("Target session to proxy cannot be null.");
        }
        delegate = target;
    }

    public Serializable getId() {
        return delegate.getId();
    }

    public Date getStartTimestamp() {
        return delegate.getStartTimestamp();
    }

    public Date getLastAccessTime() {
        return delegate.getLastAccessTime();
    }

    public long getTimeout() throws InvalidSessionException {
        return delegate.getTimeout();
    }

    public void setTimeout(long maxIdleTimeInMillis) throws InvalidSessionException {
        delegate.setTimeout(maxIdleTimeInMillis);
    }

    public String getHost() {
        return delegate.getHost();
    }

    public void touch() throws InvalidSessionException {
        delegate.touch();
    }

    public void stop() throws InvalidSessionException {
        delegate.stop();
    }


    public Collection<Object> getAttributeKeys() throws InvalidSessionException {
        return delegate.getAttributeKeys();
    }

    public Object getAttribute(Object key) throws InvalidSessionException {
        return delegate.getAttribute(key);
    }

    public void setAttribute(Object key, Object value) throws InvalidSessionException {
        delegate.setAttribute(key, value);
    }

    public Object removeAttribute(Object key) throws InvalidSessionException {
        return delegate.removeAttribute(key);
    }
}

