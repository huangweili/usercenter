package com.hwlcn.security.subject;

import com.hwlcn.security.util.CollectionUtils;

import java.util.*;

public class SimplePrincipalMap implements PrincipalMap {


    private Map<String, Map<String, Object>> realmPrincipals;

    private Map<String, Object> combinedPrincipals;

    public SimplePrincipalMap() {
        this(null);
    }

    public SimplePrincipalMap(Map<String, Map<String, Object>> backingMap) {
        if (!CollectionUtils.isEmpty(backingMap)) {
            this.realmPrincipals = backingMap;
            for (Map<String, Object> principals : this.realmPrincipals.values()) {
                if (!CollectionUtils.isEmpty(principals)) {
                    ensureCombinedPrincipals().putAll(principals);
                }
            }
        }
    }

    public int size() {
        return CollectionUtils.size(this.combinedPrincipals);
    }

    protected Map<String, Object> ensureCombinedPrincipals() {
        if (this.combinedPrincipals == null) {
            this.combinedPrincipals = new HashMap<String, Object>();
        }
        return this.combinedPrincipals;
    }

    public boolean containsKey(Object o) {
        return this.combinedPrincipals != null && this.combinedPrincipals.containsKey(o);
    }

    public boolean containsValue(Object o) {
        return this.combinedPrincipals != null && this.combinedPrincipals.containsKey(o);
    }

    public Object get(Object o) {
        return this.combinedPrincipals != null && this.combinedPrincipals.containsKey(o);
    }

    public Object put(String s, Object o) {
        return ensureCombinedPrincipals().put(s, o);
    }

    public Object remove(Object o) {
        return this.combinedPrincipals != null ? this.combinedPrincipals.remove(o) : null;
    }

    public void putAll(Map<? extends String, ?> map) {
        if (!CollectionUtils.isEmpty(map)) {
            ensureCombinedPrincipals().putAll(map);
        }
    }

    public Set<String> keySet() {
        return CollectionUtils.isEmpty(this.combinedPrincipals) ?
                Collections.<String>emptySet() :
                Collections.unmodifiableSet(this.combinedPrincipals.keySet());
    }

    public Collection<Object> values() {
        return CollectionUtils.isEmpty(this.combinedPrincipals) ?
                Collections.emptySet() :
                Collections.unmodifiableCollection(this.combinedPrincipals.values());
    }

    public Set<Entry<String, Object>> entrySet() {
        return CollectionUtils.isEmpty(this.combinedPrincipals) ?
                Collections.<Entry<String, Object>>emptySet() :
                Collections.unmodifiableSet(this.combinedPrincipals.entrySet());
    }

    public void clear() {
        this.realmPrincipals = null;
        this.combinedPrincipals = null;
    }

    public Object getPrimaryPrincipal() {
        return !CollectionUtils.isEmpty(this.combinedPrincipals) ?
                this.combinedPrincipals.values().iterator().next() :
                null;
    }

    public <T> T oneByType(Class<T> type) {
        if (CollectionUtils.isEmpty(this.combinedPrincipals)) {
            return null;
        }
        for (Object value : this.combinedPrincipals.values()) {
            if (type.isInstance(value)) {
                return type.cast(value);
            }
        }
        return null;
    }

    public <T> Collection<T> byType(Class<T> type) {
        if (CollectionUtils.isEmpty(this.combinedPrincipals)) {
            return Collections.emptySet();
        }
        Collection<T> instances = null;
        for (Object value : this.combinedPrincipals.values()) {
            if (type.isInstance(value)) {
                if (instances == null) {
                    instances = new ArrayList<T>();
                }
                instances.add(type.cast(value));
            }
        }
        return instances != null ? instances : Collections.<T>emptyList();
    }

    public List asList() {
        if (CollectionUtils.isEmpty(this.combinedPrincipals)) {
            return Collections.emptyList();
        }
        List<Object> list = new ArrayList<Object>(this.combinedPrincipals.size());
        list.addAll(this.combinedPrincipals.values());
        return list;
    }

    public Set asSet() {
        if (CollectionUtils.isEmpty(this.combinedPrincipals)) {
            return Collections.emptySet();
        }
        Set<Object> set = new HashSet<Object>(this.combinedPrincipals.size());
        set.addAll(this.combinedPrincipals.values());
        return set;
    }

    public Collection fromRealm(String realmName) {
        if (CollectionUtils.isEmpty(this.realmPrincipals)) {
            return Collections.emptySet();
        }
        Map<String, Object> principals = this.realmPrincipals.get(realmName);
        if (CollectionUtils.isEmpty(principals)) {
            return Collections.emptySet();
        }
        return Collections.unmodifiableCollection(principals.values());
    }

    public Set<String> getRealmNames() {
        if (CollectionUtils.isEmpty(this.realmPrincipals)) {
            return Collections.emptySet();
        }
        return Collections.unmodifiableSet(this.realmPrincipals.keySet());
    }

    public boolean isEmpty() {
        return CollectionUtils.isEmpty(this.combinedPrincipals);
    }

    public Iterator iterator() {
        return asList().iterator();
    }

    public Map<String, Object> getRealmPrincipals(String name) {
        if (this.realmPrincipals == null) {
            return null;
        }
        Map<String, Object> principals = this.realmPrincipals.get(name);
        if (principals == null) {
            return null;
        }
        return Collections.unmodifiableMap(principals);
    }

    public Map<String, Object> setRealmPrincipals(String realmName, Map<String, Object> principals) {
        if (realmName == null) {
            throw new NullPointerException("realmName argument cannot be null.");
        }
        if (this.realmPrincipals == null) {
            if (!CollectionUtils.isEmpty(principals)) {
                this.realmPrincipals = new HashMap<String, Map<String, Object>>();
                return this.realmPrincipals.put(realmName, new HashMap<String, Object>(principals));
            } else {
                return null;
            }
        } else {
            Map<String, Object> existingPrincipals = this.realmPrincipals.remove(realmName);
            if (!CollectionUtils.isEmpty(principals)) {
                this.realmPrincipals.put(realmName, new HashMap<String, Object>(principals));
            }
            return existingPrincipals;
        }
    }

    public Object setRealmPrincipal(String realmName, String principalName, Object principal) {
        if (realmName == null) {
            throw new NullPointerException("realmName argument cannot be null.");
        }
        if (principalName == null) {
            throw new NullPointerException(("principalName argument cannot be null."));
        }
        if (principal == null) {
            return removeRealmPrincipal(realmName, principalName);
        }
        if (this.realmPrincipals == null) {
            this.realmPrincipals = new HashMap<String, Map<String, Object>>();
        }
        Map<String, Object> principals = this.realmPrincipals.get(realmName);
        if (principals == null) {
            principals = new HashMap<String, Object>();
            this.realmPrincipals.put(realmName, principals);
        }
        return principals.put(principalName, principal);
    }

    public Object getRealmPrincipal(String realmName, String principalName) {
        if (realmName == null) {
            throw new NullPointerException("realmName argument cannot be null.");
        }
        if (principalName == null) {
            throw new NullPointerException(("principalName argument cannot be null."));
        }
        if (this.realmPrincipals == null) {
            return null;
        }
        Map<String, Object> principals = this.realmPrincipals.get(realmName);
        if (principals != null) {
            return principals.get(principalName);
        }
        return null;
    }

    public Object removeRealmPrincipal(String realmName, String principalName) {
        if (realmName == null) {
            throw new NullPointerException("realmName argument cannot be null.");
        }
        if (principalName == null) {
            throw new NullPointerException(("principalName argument cannot be null."));
        }
        if (this.realmPrincipals == null) {
            return null;
        }
        Map<String, Object> principals = this.realmPrincipals.get(realmName);
        if (principals != null) {
            return principals.remove(principalName);
        }
        return null;
    }
}
