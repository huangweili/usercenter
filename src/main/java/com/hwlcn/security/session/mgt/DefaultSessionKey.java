package com.hwlcn.security.session.mgt;

import java.io.Serializable;


public class DefaultSessionKey implements SessionKey, Serializable {

    private Serializable sessionId;

    public DefaultSessionKey() {
    }

    public DefaultSessionKey(Serializable sessionId) {
        this.sessionId = sessionId;
    }

    public void setSessionId(Serializable sessionId) {
        this.sessionId = sessionId;
    }

    public Serializable getSessionId() {
        return this.sessionId;
    }
}
