package com.hwlcn.security.env;

public class RequiredTypeException extends EnvironmentException {

    public RequiredTypeException(String message) {
        super(message);
    }

    public RequiredTypeException(String message, Throwable cause) {
        super(message, cause);
    }
}
