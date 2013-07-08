package com.hwlcn.security.subject.support;

import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.util.ThreadState;


public class SubjectRunnable implements Runnable {

    protected final ThreadState threadState;
    private final Runnable runnable;

    public SubjectRunnable(Subject subject, Runnable delegate) {
        this(new SubjectThreadState(subject), delegate);
    }

    protected SubjectRunnable(ThreadState threadState, Runnable delegate) throws IllegalArgumentException {
        if (threadState == null) {
            throw new IllegalArgumentException("ThreadState argument cannot be null.");
        }
        this.threadState = threadState;
        if (delegate == null) {
            throw new IllegalArgumentException("Runnable argument cannot be null.");
        }
        this.runnable = delegate;
    }

    public void run() {
        try {
            threadState.bind();
            doRun(this.runnable);
        } finally {
            threadState.restore();
        }
    }

    protected void doRun(Runnable runnable) {
        runnable.run();
    }
}
