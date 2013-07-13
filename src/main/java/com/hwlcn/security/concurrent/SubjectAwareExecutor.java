package com.hwlcn.security.concurrent;

import com.hwlcn.security.SecurityUtils;
import com.hwlcn.security.subject.Subject;

import java.util.concurrent.Executor;


public class SubjectAwareExecutor implements Executor {

    private Executor targetExecutor;

    public SubjectAwareExecutor() {

    }

    public SubjectAwareExecutor(Executor targetExecutor) {
        if (targetExecutor == null) {
            throw new NullPointerException("target Executor instance cannot be null.");
        }
        this.targetExecutor = targetExecutor;
    }

    public Executor getTargetExecutor() {
        return targetExecutor;
    }

    public void setTargetExecutor(Executor targetExecutor) {
        this.targetExecutor = targetExecutor;
    }

    protected Subject getSubject() {
        return SecurityUtils.getSubject();
    }

    protected Runnable associateWithSubject(Runnable r) {
        Subject subject = getSubject();
        return subject.associateWith(r);
    }

    public void execute(Runnable command) {
        Runnable associated = associateWithSubject(command);
        getTargetExecutor().execute(associated);
    }
}
