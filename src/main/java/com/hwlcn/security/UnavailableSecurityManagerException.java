package com.hwlcn.security;

import com.hwlcn.HwlcnException;

public class UnavailableSecurityManagerException extends HwlcnException {

    public UnavailableSecurityManagerException(String message) {
        super(message);
    }

    public UnavailableSecurityManagerException(String message, Throwable cause) {
        super(message, cause);
    }
}
