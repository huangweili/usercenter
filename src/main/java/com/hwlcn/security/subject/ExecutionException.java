package com.hwlcn.security.subject;


public class ExecutionException extends RuntimeException {

    public ExecutionException(Throwable cause) {
        super(cause);
    }

    public ExecutionException(String message, Throwable cause) {
        super(message, cause);
    }
}
