package com.hwlcn.ldap.util;


import com.hwlcn.core.annotation.ThreadSafety;

import java.io.Serializable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;



@ThreadSafety(level = ThreadSafetyLevel.MOSTLY_NOT_THREADSAFE)
public final class WakeableSleeper
        implements Serializable {
    private static final long serialVersionUID = 755656862953269760L;


    private final AtomicBoolean sleeping;

    private final AtomicLong wakeupCount;


    public WakeableSleeper() {
        sleeping = new AtomicBoolean(false);
        wakeupCount = new AtomicLong(0L);
    }


    @ThreadSafety(level = ThreadSafetyLevel.NOT_THREADSAFE)
    public boolean sleep(final long time) {
        synchronized (wakeupCount) {
            Validator.ensureTrue(sleeping.compareAndSet(false, true),
                    "WakeableSleeper.sleep() must not be invoked concurrently by " +
                            "multiple threads against the same instance.");

            try {
                final long beforeCount = wakeupCount.get();
                wakeupCount.wait(time);
                final long afterCount = wakeupCount.get();
                return (beforeCount == afterCount);
            } catch (final InterruptedException ie) {
                Debug.debugException(ie);
                return false;
            } finally {
                sleeping.set(false);
            }
        }
    }


    @ThreadSafety(level = ThreadSafetyLevel.COMPLETELY_THREADSAFE)
    public void wakeup() {
        synchronized (wakeupCount) {
            wakeupCount.incrementAndGet();
            wakeupCount.notifyAll();
        }
    }
}
