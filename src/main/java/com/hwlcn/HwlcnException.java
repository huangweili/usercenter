
package com.hwlcn;

/**
 * 系统异常基础
 *
 * @author huangweili
 */
public class HwlcnException extends RuntimeException {

    public HwlcnException() {
        super();
    }

    public HwlcnException(String message) {
        super(message);
    }

    public HwlcnException(Throwable throwable) {
        super(throwable);
    }

    public HwlcnException(String message, Throwable throwable) {
        super(message, throwable);
    }


    @Override()
    public final String toString() {
        final StringBuilder buffer = new StringBuilder();
        toString(buffer);
        return buffer.toString();
    }


    public void toString(final StringBuilder buffer) {
        buffer.append(super.toString());
    }


    public String getExceptionMessage() {
        final String message = getMessage();
        if (message == null) {
            return toString();
        } else {
            return message;
        }
    }
}

