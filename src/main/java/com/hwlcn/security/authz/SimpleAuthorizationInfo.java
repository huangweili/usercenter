package com.hwlcn.security.authz;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;


public class SimpleAuthorizationInfo implements AuthorizationInfo {

    protected Set<String> roles;

    protected Set<String> stringPermissions;

    protected Set<Permission> objectPermissions;

    public SimpleAuthorizationInfo() {
    }

    public SimpleAuthorizationInfo(Set<String> roles) {
        this.roles = roles;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    public void addRole(String role) {
        if (this.roles == null) {
            this.roles = new HashSet<String>();
        }
        this.roles.add(role);
    }

    public void addRoles(Collection<String> roles) {
        if (this.roles == null) {
            this.roles = new HashSet<String>();
        }
        this.roles.addAll(roles);
    }

    public Set<String> getStringPermissions() {
        return stringPermissions;
    }

    public void setStringPermissions(Set<String> stringPermissions) {
        this.stringPermissions = stringPermissions;
    }

    public void addStringPermission(String permission) {
        if (this.stringPermissions == null) {
            this.stringPermissions = new HashSet<String>();
        }
        this.stringPermissions.add(permission);
    }

    public void addStringPermissions(Collection<String> permissions) {
        if (this.stringPermissions == null) {
            this.stringPermissions = new HashSet<String>();
        }
        this.stringPermissions.addAll(permissions);
    }

    public Set<Permission> getObjectPermissions() {
        return objectPermissions;
    }

    public void setObjectPermissions(Set<Permission> objectPermissions) {
        this.objectPermissions = objectPermissions;
    }

    public void addObjectPermission(Permission permission) {
        if (this.objectPermissions == null) {
            this.objectPermissions = new HashSet<Permission>();
        }
        this.objectPermissions.add(permission);
    }

    public void addObjectPermissions(Collection<Permission> permissions) {
        if (this.objectPermissions == null) {
            this.objectPermissions = new HashSet<Permission>();
        }
        this.objectPermissions.addAll(permissions);
    }
}
