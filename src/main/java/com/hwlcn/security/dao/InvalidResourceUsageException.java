
package com.hwlcn.security.dao;

public class InvalidResourceUsageException extends DataAccessException {


    public InvalidResourceUsageException(String message) {
        super(message);
    }


    public InvalidResourceUsageException(String message, Throwable cause) {
        super(message, cause);
    }
}
