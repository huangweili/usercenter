
package com.hwlcn.security.authc;

/**
 * 用户不存在时抛出的异常
 */
public class UnknownAccountException extends AccountException {


    public UnknownAccountException() {
        super();
    }


    public UnknownAccountException(String message) {
        super(message);
    }


    public UnknownAccountException(Throwable cause) {
        super(cause);
    }


    public UnknownAccountException(String message, Throwable cause) {
        super(message, cause);
    }
}
