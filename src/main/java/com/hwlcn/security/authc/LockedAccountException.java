package com.hwlcn.security.authc;


public class LockedAccountException extends DisabledAccountException {

    public LockedAccountException() {
        super();
    }

    public LockedAccountException(String message) {
        super(message);
    }

    public LockedAccountException(Throwable cause) {
        super(cause);
    }

    public LockedAccountException(String message, Throwable cause) {
        super(message, cause);
    }

}
