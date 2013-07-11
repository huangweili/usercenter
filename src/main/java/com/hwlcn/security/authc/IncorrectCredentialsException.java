package com.hwlcn.security.authc;


public class IncorrectCredentialsException extends CredentialsException {

    public IncorrectCredentialsException() {
        super();
    }

    public IncorrectCredentialsException(String message) {
        super(message);
    }

    public IncorrectCredentialsException(Throwable cause) {
        super(cause);
    }

    public IncorrectCredentialsException(String message, Throwable cause) {
        super(message, cause);
    }

}
