package com.hwlcn.security.authc;


public class ExpiredCredentialsException extends CredentialsException {

    public ExpiredCredentialsException() {
        super();
    }

    public ExpiredCredentialsException(String message) {
        super(message);
    }

    public ExpiredCredentialsException(Throwable cause) {
        super(cause);
    }

    public ExpiredCredentialsException(String message, Throwable cause) {
        super(message, cause);
    }
}
