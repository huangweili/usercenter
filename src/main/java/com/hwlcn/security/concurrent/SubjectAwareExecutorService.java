package com.hwlcn.security.concurrent;

import com.hwlcn.security.subject.Subject;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.*;


public class SubjectAwareExecutorService extends SubjectAwareExecutor implements ExecutorService {

    private ExecutorService targetExecutorService;

    public SubjectAwareExecutorService() {
    }

    public SubjectAwareExecutorService(ExecutorService target) {
        setTargetExecutorService(target);
    }

    public ExecutorService getTargetExecutorService() {
        return targetExecutorService;
    }

    public void setTargetExecutorService(ExecutorService targetExecutorService) {
        super.setTargetExecutor(targetExecutorService);
        this.targetExecutorService = targetExecutorService;
    }

    @Override
    public void setTargetExecutor(Executor targetExecutor) {
        if (!(targetExecutor instanceof ExecutorService)) {
            String msg = "The " + getClass().getName() + " implementation only accepts " +
                    ExecutorService.class.getName() + " target instances.";
            throw new IllegalArgumentException(msg);
        }
        super.setTargetExecutor(targetExecutor);
    }

    public void shutdown() {
        this.targetExecutorService.shutdown();
    }

    public List<Runnable> shutdownNow() {
        return this.targetExecutorService.shutdownNow();
    }

    public boolean isShutdown() {
        return this.targetExecutorService.isShutdown();
    }

    public boolean isTerminated() {
        return this.targetExecutorService.isTerminated();
    }

    public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
        return this.targetExecutorService.awaitTermination(timeout, unit);
    }

    protected <T> Callable<T> associateWithSubject(Callable<T> task) {
        Subject subject = getSubject();
        return subject.associateWith(task);
    }

    public <T> Future<T> submit(Callable<T> task) {
        Callable<T> work = associateWithSubject(task);
        return this.targetExecutorService.submit(work);
    }

    public <T> Future<T> submit(Runnable task, T result) {
        Runnable work = associateWithSubject(task);
        return this.targetExecutorService.submit(work, result);
    }

    public Future<?> submit(Runnable task) {
        Runnable work = associateWithSubject(task);
        return this.targetExecutorService.submit(work);
    }

    protected <T> Collection<Callable<T>> associateWithSubject(Collection<? extends Callable<T>> tasks) {
        Collection<Callable<T>> workItems = new ArrayList<Callable<T>>(tasks.size());
        for (Callable<T> task : tasks) {
            Callable<T> work = associateWithSubject(task);
            workItems.add(work);
        }
        return workItems;
    }

    public <T> List<Future<T>> invokeAll(Collection<? extends Callable<T>> tasks) throws InterruptedException {
        Collection<Callable<T>> workItems = associateWithSubject(tasks);
        return this.targetExecutorService.invokeAll(workItems);
    }

    public <T> List<Future<T>> invokeAll(Collection<? extends Callable<T>> tasks, long timeout, TimeUnit unit)
            throws InterruptedException {
        Collection<Callable<T>> workItems = associateWithSubject(tasks);
        return this.targetExecutorService.invokeAll(workItems, timeout, unit);
    }

    public <T> T invokeAny(Collection<? extends Callable<T>> tasks) throws InterruptedException, ExecutionException {
        Collection<Callable<T>> workItems = associateWithSubject(tasks);
        return this.targetExecutorService.invokeAny(workItems);
    }

    public <T> T invokeAny(Collection<? extends Callable<T>> tasks, long timeout, TimeUnit unit)
            throws InterruptedException, ExecutionException, TimeoutException {
        Collection<Callable<T>> workItems = associateWithSubject(tasks);
        return this.targetExecutorService.invokeAny(workItems, timeout, unit);
    }
}
