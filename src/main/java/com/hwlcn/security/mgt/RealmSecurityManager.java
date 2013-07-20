
package com.hwlcn.security.mgt;

import com.hwlcn.security.util.LifecycleUtils;
import com.hwlcn.cache.CacheManager;
import com.hwlcn.cache.CacheManagerAware;
import com.hwlcn.security.realm.Realm;

import java.util.ArrayList;
import java.util.Collection;



public abstract class RealmSecurityManager extends CachingSecurityManager {


    private Collection<Realm> realms;


    public RealmSecurityManager() {
        super();
    }


    public void setRealm(Realm realm) {
        if (realm == null) {
            throw new IllegalArgumentException("Realm argument cannot be null");
        }
        Collection<Realm> realms = new ArrayList<Realm>(1);
        realms.add(realm);
        setRealms(realms);
    }


    public void setRealms(Collection<Realm> realms) {
        if (realms == null) {
            throw new IllegalArgumentException("Realms collection argument cannot be null.");
        }
        if (realms.isEmpty()) {
            throw new IllegalArgumentException("Realms collection argument cannot be empty.");
        }
        this.realms = realms;
        afterRealmsSet();
    }

    protected void afterRealmsSet() {
        applyCacheManagerToRealms();
    }


    public Collection<Realm> getRealms() {
        return realms;
    }


    protected void applyCacheManagerToRealms() {
        CacheManager cacheManager = getCacheManager();
        Collection<Realm> realms = getRealms();
        if (cacheManager != null && realms != null && !realms.isEmpty()) {
            for (Realm realm : realms) {
                if (realm instanceof CacheManagerAware) {
                    ((CacheManagerAware) realm).setCacheManager(cacheManager);
                }
            }
        }
    }


    protected void afterCacheManagerSet() {
        applyCacheManagerToRealms();
    }

    public void destroy() {
        LifecycleUtils.destroy(getRealms());
        this.realms = null;
        super.destroy();
    }

}
