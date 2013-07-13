package com.hwlcn.security.session.mgt.eis;

import com.hwlcn.security.session.Session;

import java.io.Serializable;
import java.util.UUID;

public class JavaUuidSessionIdGenerator implements SessionIdGenerator {


    public Serializable generateId(Session session) {
        return UUID.randomUUID().toString();
    }
}
