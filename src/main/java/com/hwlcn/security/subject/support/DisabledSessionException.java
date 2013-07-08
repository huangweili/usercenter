package com.hwlcn.security.subject.support;

import com.hwlcn.security.session.SessionException;


public class DisabledSessionException extends SessionException {

    public DisabledSessionException(String message) {
        super(message);
    }
}
