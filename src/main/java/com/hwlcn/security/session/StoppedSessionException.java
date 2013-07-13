package com.hwlcn.security.session;

public class StoppedSessionException extends InvalidSessionException {

    public StoppedSessionException() {
        super();
    }

    public StoppedSessionException(String message) {
        super(message);
    }

    public StoppedSessionException(Throwable cause) {
        super(cause);
    }

    public StoppedSessionException(String message, Throwable cause) {
        super(message, cause);
    }

}
