package com.hwlcn.cache;

import java.util.Collection;
import java.util.Set;


public interface Cache<K, V> {

    public V get(K key) throws CacheException;

    public V put(K key, V value) throws CacheException;

    public V remove(K key) throws CacheException;

    public void clear() throws CacheException;

    public int size();

    public Set<K> keys();

    public Collection<V> values();
}
