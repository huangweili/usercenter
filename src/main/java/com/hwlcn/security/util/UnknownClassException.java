package com.hwlcn.security.util;



public class UnknownClassException extends RuntimeException {

    public UnknownClassException() {
        super();
    }

    public UnknownClassException(String message) {
        super(message);
    }

    public UnknownClassException(Throwable cause) {
        super(cause);
    }

    public UnknownClassException(String message, Throwable cause) {
        super(message, cause);
    }

}
