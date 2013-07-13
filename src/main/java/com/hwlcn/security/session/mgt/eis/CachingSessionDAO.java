package com.hwlcn.security.session.mgt.eis;

import com.hwlcn.security.session.Session;
import com.hwlcn.security.session.mgt.ValidatingSession;
import com.hwlcn.cache.Cache;
import com.hwlcn.cache.CacheManager;
import com.hwlcn.cache.CacheManagerAware;
import com.hwlcn.security.session.UnknownSessionException;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;

public abstract class CachingSessionDAO extends AbstractSessionDAO implements CacheManagerAware {

    public static final String ACTIVE_SESSION_CACHE_NAME = "secrity-activeSessionCache";

    private CacheManager cacheManager;

    private Cache<Serializable, Session> activeSessions;

    private String activeSessionsCacheName = ACTIVE_SESSION_CACHE_NAME;

    public CachingSessionDAO() {
    }

    public void setCacheManager(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    public CacheManager getCacheManager() {
        return cacheManager;
    }

    public String getActiveSessionsCacheName() {
        return activeSessionsCacheName;
    }

    public void setActiveSessionsCacheName(String activeSessionsCacheName) {
        this.activeSessionsCacheName = activeSessionsCacheName;
    }

    public Cache<Serializable, Session> getActiveSessionsCache() {
        return this.activeSessions;
    }

    public void setActiveSessionsCache(Cache<Serializable, Session> cache) {
        this.activeSessions = cache;
    }

    private Cache<Serializable, Session> getActiveSessionsCacheLazy() {
        if (this.activeSessions == null) {
            this.activeSessions = createActiveSessionsCache();
        }
        return activeSessions;
    }

    protected Cache<Serializable, Session> createActiveSessionsCache() {
        Cache<Serializable, Session> cache = null;
        CacheManager mgr = getCacheManager();
        if (mgr != null) {
            String name = getActiveSessionsCacheName();
            cache = mgr.getCache(name);
        }
        return cache;
    }


    public Serializable create(Session session) {
        Serializable sessionId = super.create(session);
        cache(session, sessionId);
        return sessionId;
    }


    protected Session getCachedSession(Serializable sessionId) {
        Session cached = null;
        if (sessionId != null) {
            Cache<Serializable, Session> cache = getActiveSessionsCacheLazy();
            if (cache != null) {
                cached = getCachedSession(sessionId, cache);
            }
        }
        return cached;
    }


    protected Session getCachedSession(Serializable sessionId, Cache<Serializable, Session> cache) {
        return cache.get(sessionId);
    }


    protected void cache(Session session, Serializable sessionId) {
        if (session == null || sessionId == null) {
            return;
        }
        Cache<Serializable, Session> cache = getActiveSessionsCacheLazy();
        if (cache == null) {
            return;
        }
        cache(session, sessionId, cache);
    }


    protected void cache(Session session, Serializable sessionId, Cache<Serializable, Session> cache) {
        cache.put(sessionId, session);
    }


    public Session readSession(Serializable sessionId) throws UnknownSessionException {
        Session s = getCachedSession(sessionId);
        if (s == null) {
            s = super.readSession(sessionId);
        }
        return s;
    }


    public void update(Session session) throws UnknownSessionException {
        doUpdate(session);
        if (session instanceof ValidatingSession) {
            if (((ValidatingSession) session).isValid()) {
                cache(session, session.getId());
            } else {
                uncache(session);
            }
        } else {
            cache(session, session.getId());
        }
    }


    protected abstract void doUpdate(Session session);


    public void delete(Session session) {
        uncache(session);
        doDelete(session);
    }


    protected abstract void doDelete(Session session);


    protected void uncache(Session session) {
        if (session == null) {
            return;
        }
        Serializable id = session.getId();
        if (id == null) {
            return;
        }
        Cache<Serializable, Session> cache = getActiveSessionsCacheLazy();
        if (cache != null) {
            cache.remove(id);
        }
    }


    public Collection<Session> getActiveSessions() {
        Cache<Serializable, Session> cache = getActiveSessionsCacheLazy();
        if (cache != null) {
            return cache.values();
        } else {
            return Collections.emptySet();
        }
    }
}
