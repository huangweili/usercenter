package com.hwlcn.security.authc;


public class ConcurrentAccessException extends AccountException {

    public ConcurrentAccessException() {
        super();
    }

    public ConcurrentAccessException(String message) {
        super(message);
    }

    public ConcurrentAccessException(Throwable cause) {
        super(cause);
    }

    public ConcurrentAccessException(String message, Throwable cause) {
        super(message, cause);
    }

}
