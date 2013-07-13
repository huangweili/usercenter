package com.hwlcn.security.util;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.SoftReference;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.locks.ReentrantLock;


public class SoftHashMap<K, V> implements Map<K, V> {

    private static final int DEFAULT_RETENTION_SIZE = 100;

    private final Map<K, SoftValue<V, K>> map;

    private final int RETENTION_SIZE;

    private final Queue<V> strongReferences; //guarded by 'strongReferencesLock'
    private final ReentrantLock strongReferencesLock;

    private final ReferenceQueue<? super V> queue;

    public SoftHashMap() {
        this(DEFAULT_RETENTION_SIZE);
    }

    @SuppressWarnings({"unchecked"})
    public SoftHashMap(int retentionSize) {
        super();
        RETENTION_SIZE = Math.max(0, retentionSize);
        queue = new ReferenceQueue<V>();
        strongReferencesLock = new ReentrantLock();
        map = new ConcurrentHashMap<K, SoftValue<V, K>>();
        strongReferences = new ConcurrentLinkedQueue<V>();
    }

    public SoftHashMap(Map<K, V> source) {
        this(DEFAULT_RETENTION_SIZE);
        putAll(source);
    }

    public SoftHashMap(Map<K, V> source, int retentionSize) {
        this(retentionSize);
        putAll(source);
    }

    public V get(Object key) {
        processQueue();

        V result = null;
        SoftValue<V, K> value = map.get(key);

        if (value != null) {
            //unwrap the 'real' value from the SoftReference
            result = value.get();
            if (result == null) {
                //The wrapped value was garbage collected, so remove this entry from the backing map:
                //noinspection SuspiciousMethodCalls
                map.remove(key);
            } else {
                //Add this value to the beginning of the strong reference queue (FIFO).
                addToStrongReferences(result);
            }
        }
        return result;
    }

    private void addToStrongReferences(V result) {
        strongReferencesLock.lock();
        try {
            strongReferences.add(result);
            trimStrongReferencesIfNecessary();
        } finally {
            strongReferencesLock.unlock();
        }

    }

  private void trimStrongReferencesIfNecessary() {
        while (strongReferences.size() > RETENTION_SIZE) {
            strongReferences.poll();
        }
    }

    private void processQueue() {
        SoftValue sv;
        while ((sv = (SoftValue) queue.poll()) != null) {
            map.remove(sv.key); // we can access private data!
        }
    }

    public boolean isEmpty() {
        processQueue();
        return map.isEmpty();
    }

    public boolean containsKey(Object key) {
        processQueue();
        return map.containsKey(key);
    }

    public boolean containsValue(Object value) {
        processQueue();
        Collection values = values();
        return values != null && values.contains(value);
    }

    public void putAll(Map<? extends K, ? extends V> m) {
        if (m == null || m.isEmpty()) {
            processQueue();
            return;
        }
        for (Entry<? extends K, ? extends V> entry : m.entrySet()) {
            put(entry.getKey(), entry.getValue());
        }
    }

    public Set<K> keySet() {
        processQueue();
        return map.keySet();
    }

    public Collection<V> values() {
        processQueue();
        Collection<K> keys = map.keySet();
        if (keys.isEmpty()) {
            //noinspection unchecked
            return Collections.EMPTY_SET;
        }
        Collection<V> values = new ArrayList<V>(keys.size());
        for (K key : keys) {
            V v = get(key);
            if (v != null) {
                values.add(v);
            }
        }
        return values;
    }

    public V put(K key, V value) {
        processQueue();
        SoftValue<V, K> sv = new SoftValue<V, K>(value, key, queue);
        SoftValue<V, K> previous = map.put(key, sv);
        addToStrongReferences(value);
        return previous != null ? previous.get() : null;
    }

    public V remove(Object key) {
        processQueue(); // throw out garbage collected values first
        SoftValue<V, K> raw = map.remove(key);
        return raw != null ? raw.get() : null;
    }

    public void clear() {
        strongReferencesLock.lock();
        try {
            strongReferences.clear();
        } finally {
            strongReferencesLock.unlock();
        }
        processQueue();
        map.clear();
    }

    public int size() {
        processQueue();
        return map.size();
    }

    public Set<Entry<K, V>> entrySet() {
        processQueue();
        Collection<K> keys = map.keySet();
        if (keys.isEmpty()) {
            return Collections.EMPTY_SET;
        }

        Map<K, V> kvPairs = new HashMap<K, V>(keys.size());
        for (K key : keys) {
            V v = get(key);
            if (v != null) {
                kvPairs.put(key, v);
            }
        }
        return kvPairs.entrySet();
    }

    private static class SoftValue<V, K> extends SoftReference<V> {

        private final K key;

        private SoftValue(V value, K key, ReferenceQueue<? super V> queue) {
            super(value, queue);
            this.key = key;
        }

    }
}
