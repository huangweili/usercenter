package com.hwlcn.security.authc;


public class AuthenticationException extends RuntimeException {


    public AuthenticationException() {
        super();
    }


    public AuthenticationException(String message) {
        super(message);
    }

    public AuthenticationException(Throwable cause) {
        super(cause);
    }

    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
