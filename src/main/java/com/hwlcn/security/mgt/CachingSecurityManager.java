
package com.hwlcn.security.mgt;

import com.hwlcn.security.util.Destroyable;
import com.hwlcn.security.util.LifecycleUtils;
import com.hwlcn.cache.CacheManager;
import com.hwlcn.cache.CacheManagerAware;


public abstract class CachingSecurityManager implements SecurityManager, Destroyable, CacheManagerAware {

    private CacheManager cacheManager;

    public CachingSecurityManager() {
    }

    public CacheManager getCacheManager() {
        return cacheManager;
    }

    public void setCacheManager(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
        afterCacheManagerSet();
    }

    protected void afterCacheManagerSet() {
    }

    public void destroy() {
        LifecycleUtils.destroy(getCacheManager());
        this.cacheManager = null;
    }

}
