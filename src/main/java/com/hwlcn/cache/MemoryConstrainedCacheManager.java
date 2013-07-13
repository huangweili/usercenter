package com.hwlcn.cache;

import com.hwlcn.security.util.SoftHashMap;

public class MemoryConstrainedCacheManager extends AbstractCacheManager {


    @Override
    protected Cache createCache(String name) {
        return new MapCache<Object, Object>(name, new SoftHashMap<Object, Object>());
    }
}
