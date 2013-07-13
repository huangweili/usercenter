package com.hwlcn.security.mgt;

import com.hwlcn.cache.CacheManagerAware;
import com.hwlcn.security.authz.AuthorizationException;
import com.hwlcn.security.session.Session;
import com.hwlcn.security.session.SessionException;
import com.hwlcn.security.session.mgt.DefaultSessionManager;
import com.hwlcn.security.session.mgt.SessionContext;
import com.hwlcn.security.session.mgt.SessionKey;
import com.hwlcn.security.session.mgt.SessionManager;
import com.hwlcn.security.util.LifecycleUtils;


public abstract class SessionsSecurityManager extends AuthorizingSecurityManager {

    private SessionManager sessionManager;

    public SessionsSecurityManager() {
        super();
        this.sessionManager = new DefaultSessionManager();
        applyCacheManagerToSessionManager();
    }

    public void setSessionManager(SessionManager sessionManager) {
        this.sessionManager = sessionManager;
        afterSessionManagerSet();
    }

    protected void afterSessionManagerSet() {
        applyCacheManagerToSessionManager();
    }

    public SessionManager getSessionManager() {
        return this.sessionManager;
    }

    protected void afterCacheManagerSet() {
        super.afterCacheManagerSet();
        applyCacheManagerToSessionManager();
    }

    protected void applyCacheManagerToSessionManager() {
        if (this.sessionManager instanceof CacheManagerAware) {
            ((CacheManagerAware) this.sessionManager).setCacheManager(getCacheManager());
        }
    }

    public Session start(SessionContext context) throws AuthorizationException {
        return this.sessionManager.start(context);
    }

    public Session getSession(SessionKey key) throws SessionException {
        return this.sessionManager.getSession(key);
    }

    public void destroy() {
        LifecycleUtils.destroy(getSessionManager());
        this.sessionManager = null;
        super.destroy();
    }
}
