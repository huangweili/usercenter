package com.hwlcn.security.authc;

public class DisabledAccountException extends AccountException {

    public DisabledAccountException() {
        super();
    }

    public DisabledAccountException(String message) {
        super(message);
    }

    public DisabledAccountException(Throwable cause) {
        super(cause);
    }

    public DisabledAccountException(String message, Throwable cause) {
        super(message, cause);
    }
}
