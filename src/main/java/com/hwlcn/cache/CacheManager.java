package com.hwlcn.cache;


public interface CacheManager {

    public <K, V> Cache<K, V> getCache(String name) throws CacheException;
}
