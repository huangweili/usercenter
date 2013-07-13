package com.hwlcn.security.util;

import java.io.Serializable;
import java.util.*;


public class MapContext implements Map<String, Object>, Serializable {

    private static final long serialVersionUID = 5373399119017820322L;

    private final Map<String, Object> backingMap;

    public MapContext() {
        this.backingMap = new HashMap<String, Object>();
    }

    public MapContext(Map<String, Object> map) {
        this();
        if (!CollectionUtils.isEmpty(map)) {
            this.backingMap.putAll(map);
        }
    }

    protected <E> E getTypedValue(String key, Class<E> type) {
        E found = null;
        Object o = backingMap.get(key);
        if (o != null) {
            if (!type.isAssignableFrom(o.getClass())) {
                String msg = "Invalid object found in SubjectContext Map under key [" + key + "].  Expected type " +
                        "was [" + type.getName() + "], but the object under that key is of type " +
                        "[" + o.getClass().getName() + "].";
                throw new IllegalArgumentException(msg);
            }
            found = (E) o;
        }
        return found;
    }


    protected void nullSafePut(String key, Object value) {
        if (value != null) {
            put(key, value);
        }
    }

    public int size() {
        return backingMap.size();
    }

    public boolean isEmpty() {
        return backingMap.isEmpty();
    }

    public boolean containsKey(Object o) {
        return backingMap.containsKey(o);
    }

    public boolean containsValue(Object o) {
        return backingMap.containsValue(o);
    }

    public Object get(Object o) {
        return backingMap.get(o);
    }

    public Object put(String s, Object o) {
        return backingMap.put(s, o);
    }

    public Object remove(Object o) {
        return backingMap.remove(o);
    }

    public void putAll(Map<? extends String, ?> map) {
        backingMap.putAll(map);
    }

    public void clear() {
        backingMap.clear();
    }

    public Set<String> keySet() {
        return Collections.unmodifiableSet(backingMap.keySet());
    }

    public Collection<Object> values() {
        return Collections.unmodifiableCollection(backingMap.values());
    }

    public Set<Entry<String, Object>> entrySet() {
        return Collections.unmodifiableSet(backingMap.entrySet());
    }
}
