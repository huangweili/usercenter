
package com.hwlcn.security.dao;


public abstract class DataAccessException extends RuntimeException {


    public DataAccessException(String message) {
        super(message);
    }


    public DataAccessException(String message, Throwable cause) {
        super(message, cause);
    }
}
