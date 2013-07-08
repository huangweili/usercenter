package com.hwlcn.security.web.mgt;

import com.hwlcn.security.mgt.DefaultSessionStorageEvaluator;
import com.hwlcn.security.session.mgt.NativeSessionManager;
import com.hwlcn.security.session.mgt.SessionManager;
import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.web.subject.WebSubject;
import com.hwlcn.security.web.util.WebUtils;


public class DefaultWebSessionStorageEvaluator extends DefaultSessionStorageEvaluator {

    private SessionManager sessionManager;

    void setSessionManager(SessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }

    @SuppressWarnings({"SimplifiableIfStatement"})
    @Override
    public boolean isSessionStorageEnabled(Subject subject) {
        if (subject.getSession(false) != null) {
            return true;
        }

        if (!isSessionStorageEnabled()) {
            return false;
        }

        if (!(subject instanceof WebSubject) && (this.sessionManager != null && !(this.sessionManager instanceof NativeSessionManager))) {
            return false;
        }

        return WebUtils._isSessionCreationEnabled(subject);
    }
}