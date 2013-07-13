package com.hwlcn.security.env;

import com.hwlcn.security.mgt.SecurityManager;
import com.hwlcn.security.util.Destroyable;
import com.hwlcn.security.util.LifecycleUtils;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


public class DefaultEnvironment implements NamedObjectEnvironment, Destroyable {


    public static final String DEFAULT_SECURITY_MANAGER_KEY = "securityManager";

    protected final Map<String, Object> objects;
    private String securityManagerName;

    public DefaultEnvironment() {
        this(new ConcurrentHashMap<String, Object>());
    }

    @SuppressWarnings({"unchecked"})
    public DefaultEnvironment(Map<String, ?> seed) {
        this.securityManagerName = DEFAULT_SECURITY_MANAGER_KEY;
        if (seed == null) {
            throw new IllegalArgumentException("Backing map cannot be null.");
        }
        this.objects = (Map<String, Object>) seed;
    }

    public com.hwlcn.security.mgt.SecurityManager getSecurityManager() throws IllegalStateException {
        SecurityManager securityManager = lookupSecurityManager();
        if (securityManager == null) {
            throw new IllegalStateException("No SecurityManager found in Environment.  This is an invalid " +
                    "environment state.");
        }
        return securityManager;
    }

    public void setSecurityManager(SecurityManager securityManager) {
        if (securityManager == null) {
            throw new IllegalArgumentException("Null SecurityManager instances are not allowed.");
        }
        String name = getSecurityManagerName();
        setObject(name, securityManager);
    }

    protected SecurityManager lookupSecurityManager() {
        String name = getSecurityManagerName();
        return getObject(name, SecurityManager.class);
    }

    public String getSecurityManagerName() {
        return securityManagerName;
    }

    public void setSecurityManagerName(String securityManagerName) {
        this.securityManagerName = securityManagerName;
    }

    public Map<String,Object> getObjects() {
        return this.objects;
    }

    @SuppressWarnings({"unchecked"})
    public <T> T getObject(String name, Class<T> requiredType) throws RequiredTypeException {
        if (name == null) {
            throw new NullPointerException("name parameter cannot be null.");
        }
        if (requiredType == null) {
            throw new NullPointerException("requiredType parameter cannot be null.");
        }
        Object o = this.objects.get(name);
        if (o == null) {
            return null;
        }
        if (!requiredType.isInstance(o)) {
            String msg = "Object named '" + name + "' is not of required type [" + requiredType.getName() + "].";
            throw new RequiredTypeException(msg);
        }
        return (T)o;
    }

    public void setObject(String name, Object instance) {
        if (name == null) {
            throw new NullPointerException("name parameter cannot be null.");
        }
        if (instance == null) {
            this.objects.remove(name);
        } else {
            this.objects.put(name, instance);
        }
    }


    public void destroy() throws Exception {
        LifecycleUtils.destroy(this.objects.values());
    }
}
