package com.hwlcn.security.authc;

import com.hwlcn.security.authz.Permission;
import com.hwlcn.security.authz.SimpleAuthorizationInfo;
import com.hwlcn.security.util.ByteSource;
import com.hwlcn.security.subject.PrincipalCollection;
import com.hwlcn.security.subject.SimplePrincipalCollection;

import java.io.Serializable;
import java.util.Collection;
import java.util.Set;


public class SimpleAccount implements Account, MergableAuthenticationInfo, SaltedAuthenticationInfo, Serializable {


    private SimpleAuthenticationInfo authcInfo;

    private SimpleAuthorizationInfo authzInfo;

    private boolean locked;

    private boolean credentialsExpired;

    public SimpleAccount() {
    }

    public SimpleAccount(Object principal, Object credentials, String realmName) {
        this(principal instanceof PrincipalCollection ? (PrincipalCollection) principal : new SimplePrincipalCollection(principal, realmName), credentials);
    }

    public SimpleAccount(Object principal, Object hashedCredentials, ByteSource credentialsSalt, String realmName) {
        this(principal instanceof PrincipalCollection ? (PrincipalCollection) principal : new SimplePrincipalCollection(principal, realmName),
                hashedCredentials, credentialsSalt);
    }

    public SimpleAccount(Collection principals, Object credentials, String realmName) {
        this(new SimplePrincipalCollection(principals, realmName), credentials);
    }

    public SimpleAccount(PrincipalCollection principals, Object credentials) {
        this.authcInfo = new SimpleAuthenticationInfo(principals, credentials);
        this.authzInfo = new SimpleAuthorizationInfo();
    }


    public SimpleAccount(PrincipalCollection principals, Object hashedCredentials, ByteSource credentialsSalt) {
        this.authcInfo = new SimpleAuthenticationInfo(principals, hashedCredentials, credentialsSalt);
        this.authzInfo = new SimpleAuthorizationInfo();
    }

    public SimpleAccount(PrincipalCollection principals, Object credentials, Set<String> roles) {
        this.authcInfo = new SimpleAuthenticationInfo(principals, credentials);
        this.authzInfo = new SimpleAuthorizationInfo(roles);
    }

    public SimpleAccount(Object principal, Object credentials, String realmName, Set<String> roleNames, Set<Permission> permissions) {
        this.authcInfo = new SimpleAuthenticationInfo(new SimplePrincipalCollection(principal, realmName), credentials);
        this.authzInfo = new SimpleAuthorizationInfo(roleNames);
        this.authzInfo.setObjectPermissions(permissions);
    }

    public SimpleAccount(Collection principals, Object credentials, String realmName, Set<String> roleNames, Set<Permission> permissions) {
        this.authcInfo = new SimpleAuthenticationInfo(new SimplePrincipalCollection(principals, realmName), credentials);
        this.authzInfo = new SimpleAuthorizationInfo(roleNames);
        this.authzInfo.setObjectPermissions(permissions);
    }

    public SimpleAccount(PrincipalCollection principals, Object credentials, Set<String> roleNames, Set<Permission> permissions) {
        this.authcInfo = new SimpleAuthenticationInfo(principals, credentials);
        this.authzInfo = new SimpleAuthorizationInfo(roleNames);
        this.authzInfo.setObjectPermissions(permissions);
    }

    public PrincipalCollection getPrincipals() {
        return authcInfo.getPrincipals();
    }

    public void setPrincipals(PrincipalCollection principals) {
        this.authcInfo.setPrincipals(principals);
    }


    public Object getCredentials() {
        return authcInfo.getCredentials();
    }

    public void setCredentials(Object credentials) {
        this.authcInfo.setCredentials(credentials);
    }

    public ByteSource getCredentialsSalt() {
        return this.authcInfo.getCredentialsSalt();
    }

    public void setCredentialsSalt(ByteSource salt) {
        this.authcInfo.setCredentialsSalt(salt);
    }

    public Collection<String> getRoles() {
        return authzInfo.getRoles();
    }

    public void setRoles(Set<String> roles) {
        this.authzInfo.setRoles(roles);
    }

    public void addRole(String role) {
        this.authzInfo.addRole(role);
    }

    public void addRole(Collection<String> roles) {
        this.authzInfo.addRoles(roles);
    }

    public Collection<String> getStringPermissions() {
        return authzInfo.getStringPermissions();
    }

    public void setStringPermissions(Set<String> permissions) {
        this.authzInfo.setStringPermissions(permissions);
    }

    public void addStringPermission(String permission) {
        this.authzInfo.addStringPermission(permission);
    }

    public void addStringPermissions(Collection<String> permissions) {
        this.authzInfo.addStringPermissions(permissions);
    }

    public Collection<Permission> getObjectPermissions() {
        return authzInfo.getObjectPermissions();
    }

    public void setObjectPermissions(Set<Permission> permissions) {
        this.authzInfo.setObjectPermissions(permissions);
    }

    public void addObjectPermission(Permission permission) {
        this.authzInfo.addObjectPermission(permission);
    }

    public void addObjectPermissions(Collection<Permission> permissions) {
        this.authzInfo.addObjectPermissions(permissions);
    }

    public boolean isLocked() {
        return locked;
    }

    public void setLocked(boolean locked) {
        this.locked = locked;
    }

    public boolean isCredentialsExpired() {
        return credentialsExpired;
    }

    public void setCredentialsExpired(boolean credentialsExpired) {
        this.credentialsExpired = credentialsExpired;
    }


    public void merge(AuthenticationInfo info) {
        authcInfo.merge(info);

        if (info instanceof SimpleAccount) {
            SimpleAccount otherAccount = (SimpleAccount) info;
            if (otherAccount.isLocked()) {
                setLocked(true);
            }

            if (otherAccount.isCredentialsExpired()) {
                setCredentialsExpired(true);
            }
        }
    }

    public int hashCode() {
        return (getPrincipals() != null ? getPrincipals().hashCode() : 0);
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof SimpleAccount) {
            SimpleAccount sa = (SimpleAccount) o;
            return (getPrincipals() != null ? getPrincipals().equals(sa.getPrincipals()) : sa.getPrincipals() == null);
        }
        return false;
    }

    public String toString() {
        return getPrincipals() != null ? getPrincipals().toString() : "empty";
    }

}