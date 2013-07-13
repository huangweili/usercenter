package com.hwlcn.security.mgt;

import com.hwlcn.security.subject.Subject;


public class DefaultSessionStorageEvaluator implements SessionStorageEvaluator {

    private boolean sessionStorageEnabled = true;

    public boolean isSessionStorageEnabled(Subject subject) {
        return (subject != null && subject.getSession(false) != null) || isSessionStorageEnabled();
    }

    public boolean isSessionStorageEnabled() {
        return sessionStorageEnabled;
    }

    public void setSessionStorageEnabled(boolean sessionStorageEnabled) {
        this.sessionStorageEnabled = sessionStorageEnabled;
    }
}
