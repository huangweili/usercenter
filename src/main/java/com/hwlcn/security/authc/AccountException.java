package com.hwlcn.security.authc;

public class AccountException extends AuthenticationException {


    public AccountException() {
        super();
    }

    public AccountException(String message) {
        super(message);
    }

    public AccountException(Throwable cause) {
        super(cause);
    }

    public AccountException(String message, Throwable cause) {
        super(message, cause);
    }

}
