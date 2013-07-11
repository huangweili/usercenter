package com.hwlcn.security.authc;

public class CredentialsException extends AuthenticationException {


    public CredentialsException() {
        super();
    }

    public CredentialsException(String message) {
        super(message);
    }

    public CredentialsException(Throwable cause) {
        super(cause);
    }

    public CredentialsException(String message, Throwable cause) {
        super(message, cause);
    }

}
