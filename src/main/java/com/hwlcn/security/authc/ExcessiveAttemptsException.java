package com.hwlcn.security.authc;


public class ExcessiveAttemptsException extends AccountException {

    public ExcessiveAttemptsException() {
        super();
    }

    public ExcessiveAttemptsException(String message) {
        super(message);
    }

    public ExcessiveAttemptsException(Throwable cause) {
        super(cause);
    }

    public ExcessiveAttemptsException(String message, Throwable cause) {
        super(message, cause);
    }
}
