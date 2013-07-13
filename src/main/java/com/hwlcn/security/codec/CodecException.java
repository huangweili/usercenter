package com.hwlcn.security.codec;


public class CodecException extends RuntimeException {


    public CodecException() {
        super();
    }

    public CodecException(String message) {
        super(message);
    }

    public CodecException(Throwable cause) {
        super(cause);
    }

    public CodecException(String message, Throwable cause) {
        super(message, cause);
    }
}
