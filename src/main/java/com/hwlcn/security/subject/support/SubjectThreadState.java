package com.hwlcn.security.subject.support;

import com.hwlcn.security.util.CollectionUtils;
import com.hwlcn.security.util.ThreadContext;
import com.hwlcn.security.mgt.SecurityManager;
import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.util.ThreadState;

import java.util.Map;


public class SubjectThreadState implements ThreadState {

    private Map<Object, Object> originalResources;

    private final Subject subject;
    private transient SecurityManager securityManager;

    public SubjectThreadState(Subject subject) {
        if (subject == null) {
            throw new IllegalArgumentException("Subject argument cannot be null.");
        }
        this.subject = subject;

        SecurityManager securityManager = null;
        if ( subject instanceof DelegatingSubject) {
            securityManager = ((DelegatingSubject)subject).getSecurityManager();
        }
        if ( securityManager == null) {
            securityManager = ThreadContext.getSecurityManager();
        }
        this.securityManager = securityManager;
    }

    protected Subject getSubject() {
        return this.subject;
    }

    public void bind() {
        SecurityManager securityManager = this.securityManager;
        if ( securityManager == null ) {
            securityManager = ThreadContext.getSecurityManager();
        }
        this.originalResources = ThreadContext.getResources();
        ThreadContext.remove();

        ThreadContext.bind(this.subject);
        if (securityManager != null) {
            ThreadContext.bind(securityManager);
        }
    }

    public void restore() {
        ThreadContext.remove();
        if (!CollectionUtils.isEmpty(this.originalResources)) {
            ThreadContext.setResources(this.originalResources);
        }
    }

    public void clear() {
        ThreadContext.remove();
    }
}
