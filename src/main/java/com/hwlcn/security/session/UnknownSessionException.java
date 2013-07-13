package com.hwlcn.security.session;


public class UnknownSessionException extends InvalidSessionException {

    public UnknownSessionException() {
        super();
    }

    public UnknownSessionException(String message) {
        super(message);
    }

    public UnknownSessionException(Throwable cause) {
        super(cause);
    }

    public UnknownSessionException(String message, Throwable cause) {
        super(message, cause);
    }
}
