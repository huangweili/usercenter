package com.hwlcn.security.realm;

import com.hwlcn.cache.CacheManager;
import com.hwlcn.cache.CacheManagerAware;
import com.hwlcn.security.authc.LogoutAware;
import com.hwlcn.security.subject.PrincipalCollection;
import com.hwlcn.security.util.CollectionUtils;
import com.hwlcn.security.util.Nameable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.concurrent.atomic.AtomicInteger;


public abstract class CachingRealm implements Realm, Nameable, CacheManagerAware, LogoutAware {

    private static final Logger log = LoggerFactory.getLogger(CachingRealm.class);

    private static final AtomicInteger INSTANCE_COUNT = new AtomicInteger();

    private String name;
    private boolean cachingEnabled;
    private CacheManager cacheManager;

    public CachingRealm() {
        this.cachingEnabled = true;
        this.name = getClass().getName() + "_" + INSTANCE_COUNT.getAndIncrement();
    }

    public CacheManager getCacheManager() {
        return this.cacheManager;
    }

    public void setCacheManager(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
        afterCacheManagerSet();
    }

    public boolean isCachingEnabled() {
        return cachingEnabled;
    }

    public void setCachingEnabled(boolean cachingEnabled) {
        this.cachingEnabled = cachingEnabled;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    protected void afterCacheManagerSet() {
    }

    public void onLogout(PrincipalCollection principals) {
        clearCache(principals);
    }

    protected void clearCache(PrincipalCollection principals) {
        if (!CollectionUtils.isEmpty(principals)) {
            doClearCache(principals);
            if (log.isTraceEnabled()) {
                log.trace("Cleared cache entries for account with principals [{}]", principals);
            }
        }
    }

    protected void doClearCache(PrincipalCollection principals) {
    }


    protected Object getAvailablePrincipal(PrincipalCollection principals) {
        Object primary = null;
        if (!CollectionUtils.isEmpty(principals)) {
            Collection thisPrincipals = principals.fromRealm(getName());
            if (!CollectionUtils.isEmpty(thisPrincipals)) {
                primary = thisPrincipals.iterator().next();
            } else {
                primary = principals.getPrimaryPrincipal();
            }
        }

        return primary;
    }
}
