package com.hwlcn.security.session;


public class ExpiredSessionException extends StoppedSessionException {

    public ExpiredSessionException() {
        super();
    }

    public ExpiredSessionException(String message) {
        super(message);
    }

    public ExpiredSessionException(Throwable cause) {
        super(cause);
    }

    public ExpiredSessionException(String message, Throwable cause) {
        super(message, cause);
    }
}
