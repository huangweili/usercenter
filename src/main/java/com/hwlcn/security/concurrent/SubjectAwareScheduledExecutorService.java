package com.hwlcn.security.concurrent;

import java.util.concurrent.*;

public class SubjectAwareScheduledExecutorService extends SubjectAwareExecutorService implements ScheduledExecutorService {

    private ScheduledExecutorService targetScheduledExecutorService;

    public SubjectAwareScheduledExecutorService() {
    }

    public SubjectAwareScheduledExecutorService(ScheduledExecutorService target) {
        setTargetScheduledExecutorService(target);
    }

    public ScheduledExecutorService getTargetScheduledExecutorService() {
        return targetScheduledExecutorService;
    }

    public void setTargetScheduledExecutorService(ScheduledExecutorService targetScheduledExecutorService) {
        super.setTargetExecutorService(targetScheduledExecutorService);
        this.targetScheduledExecutorService = targetScheduledExecutorService;
    }

    @Override
    public void setTargetExecutor(Executor targetExecutor) {
        if (!(targetExecutor instanceof ScheduledExecutorService)) {
            String msg = "The " + getClass().getName() + " implementation only accepts " +
                    ScheduledExecutorService.class.getName() + " target instances.";
            throw new IllegalArgumentException(msg);
        }
        super.setTargetExecutorService((ScheduledExecutorService) targetExecutor);
    }

    @Override
    public void setTargetExecutorService(ExecutorService targetExecutorService) {
        if (!(targetExecutorService instanceof ScheduledExecutorService)) {
            String msg = "The " + getClass().getName() + " implementation only accepts " +
                    ScheduledExecutorService.class.getName() + " target instances.";
            throw new IllegalArgumentException(msg);
        }
        super.setTargetExecutorService(targetExecutorService);
    }

    public ScheduledFuture<?> schedule(Runnable command, long delay, TimeUnit unit) {
        Runnable work = associateWithSubject(command);
        return this.targetScheduledExecutorService.schedule(work, delay, unit);
    }

    public <V> ScheduledFuture<V> schedule(Callable<V> callable, long delay, TimeUnit unit) {
        Callable<V> work = associateWithSubject(callable);
        return this.targetScheduledExecutorService.schedule(work, delay, unit);
    }

    public ScheduledFuture<?> scheduleAtFixedRate(Runnable command, long initialDelay, long period, TimeUnit unit) {
        Runnable work = associateWithSubject(command);
        return this.targetScheduledExecutorService.scheduleAtFixedRate(work, initialDelay, period, unit);
    }

    public ScheduledFuture<?> scheduleWithFixedDelay(Runnable command, long initialDelay, long delay, TimeUnit unit) {
        Runnable work = associateWithSubject(command);
        return this.targetScheduledExecutorService.scheduleWithFixedDelay(work, initialDelay, delay, unit);
    }
}
