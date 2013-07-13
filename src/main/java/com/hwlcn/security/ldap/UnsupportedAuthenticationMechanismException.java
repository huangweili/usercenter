
package com.hwlcn.security.ldap;

import com.hwlcn.security.dao.InvalidResourceUsageException;



public class UnsupportedAuthenticationMechanismException extends InvalidResourceUsageException {

    public UnsupportedAuthenticationMechanismException(String message) {
        super(message);
    }

    public UnsupportedAuthenticationMechanismException(String message, Throwable cause) {
        super(message, cause);
    }
}
