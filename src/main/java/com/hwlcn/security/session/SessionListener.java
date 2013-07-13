package com.hwlcn.security.session;


public interface SessionListener {

    void onStart(Session session);

    void onStop(Session session);

    void onExpiration(Session session);
}
