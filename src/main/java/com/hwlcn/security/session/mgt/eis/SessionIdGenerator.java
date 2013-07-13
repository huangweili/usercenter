package com.hwlcn.security.session.mgt.eis;

import com.hwlcn.security.session.Session;

import java.io.Serializable;

public interface SessionIdGenerator {


    Serializable generateId(Session session);

}
