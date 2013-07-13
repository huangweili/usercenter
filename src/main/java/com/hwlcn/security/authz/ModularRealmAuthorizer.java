package com.hwlcn.security.authz;

import com.hwlcn.security.authz.permission.PermissionResolver;
import com.hwlcn.security.authz.permission.RolePermissionResolverAware;
import com.hwlcn.security.authz.permission.PermissionResolverAware;
import com.hwlcn.security.authz.permission.RolePermissionResolver;
import com.hwlcn.security.realm.Realm;
import com.hwlcn.security.subject.PrincipalCollection;

import java.util.Collection;
import java.util.List;


public class ModularRealmAuthorizer implements Authorizer, PermissionResolverAware, RolePermissionResolverAware {

    protected Collection<Realm> realms;
    protected PermissionResolver permissionResolver;

    protected RolePermissionResolver rolePermissionResolver;

    public ModularRealmAuthorizer() {
    }

    public ModularRealmAuthorizer(Collection<Realm> realms) {
        setRealms(realms);
    }

    public Collection<Realm> getRealms() {
        return this.realms;
    }

    public void setRealms(Collection<Realm> realms) {
        this.realms = realms;
        applyPermissionResolverToRealms();
        applyRolePermissionResolverToRealms();
    }

    public PermissionResolver getPermissionResolver() {
        return this.permissionResolver;
    }

    public void setPermissionResolver(PermissionResolver permissionResolver) {
        this.permissionResolver = permissionResolver;
        applyPermissionResolverToRealms();
    }

    protected void applyPermissionResolverToRealms() {
        PermissionResolver resolver = getPermissionResolver();
        Collection<Realm> realms = getRealms();
        if (resolver != null && realms != null && !realms.isEmpty()) {
            for (Realm realm : realms) {
                if (realm instanceof PermissionResolverAware) {
                    ((PermissionResolverAware) realm).setPermissionResolver(resolver);
                }
            }
        }
    }

    public RolePermissionResolver getRolePermissionResolver() {
        return this.rolePermissionResolver;
    }

    public void setRolePermissionResolver(RolePermissionResolver rolePermissionResolver) {
        this.rolePermissionResolver = rolePermissionResolver;
        applyRolePermissionResolverToRealms();
    }

    protected void applyRolePermissionResolverToRealms() {
        RolePermissionResolver resolver = getRolePermissionResolver();
        Collection<Realm> realms = getRealms();
        if (resolver != null && realms != null && !realms.isEmpty()) {
            for (Realm realm : realms) {
                if (realm instanceof RolePermissionResolverAware) {
                    ((RolePermissionResolverAware) realm).setRolePermissionResolver(resolver);
                }
            }
        }
    }


    protected void assertRealmsConfigured() throws IllegalStateException {
        Collection<Realm> realms = getRealms();
        if (realms == null || realms.isEmpty()) {
            String msg = "Configuration error:  No realms have been configured!  One or more realms must be " +
                    "present to execute an authorization operation.";
            throw new IllegalStateException(msg);
        }
    }

    public boolean isPermitted(PrincipalCollection principals, String permission) {
        assertRealmsConfigured();
        for (Realm realm : getRealms()) {
            if (!(realm instanceof Authorizer)) continue;
            if (((Authorizer) realm).isPermitted(principals, permission)) {
                return true;
            }
        }
        return false;
    }

    public boolean isPermitted(PrincipalCollection principals, Permission permission) {
        assertRealmsConfigured();
        for (Realm realm : getRealms()) {
            if (!(realm instanceof Authorizer)) continue;
            if (((Authorizer) realm).isPermitted(principals, permission)) {
                return true;
            }
        }
        return false;
    }

    public boolean[] isPermitted(PrincipalCollection principals, String... permissions) {
        assertRealmsConfigured();
        if (permissions != null && permissions.length > 0) {
            boolean[] isPermitted = new boolean[permissions.length];
            for (int i = 0; i < permissions.length; i++) {
                isPermitted[i] = isPermitted(principals, permissions[i]);
            }
            return isPermitted;
        }
        return new boolean[0];
    }

    public boolean[] isPermitted(PrincipalCollection principals, List<Permission> permissions) {
        assertRealmsConfigured();
        if (permissions != null && !permissions.isEmpty()) {
            boolean[] isPermitted = new boolean[permissions.size()];
            int i = 0;
            for (Permission p : permissions) {
                isPermitted[i++] = isPermitted(principals, p);
            }
            return isPermitted;
        }

        return new boolean[0];
    }

    public boolean isPermittedAll(PrincipalCollection principals, String... permissions) {
        assertRealmsConfigured();
        if (permissions != null && permissions.length > 0) {
            for (String perm : permissions) {
                if (!isPermitted(principals, perm)) {
                    return false;
                }
            }
        }
        return true;
    }


    public boolean isPermittedAll(PrincipalCollection principals, Collection<Permission> permissions) {
        assertRealmsConfigured();
        if (permissions != null && !permissions.isEmpty()) {
            for (Permission permission : permissions) {
                if (!isPermitted(principals, permission)) {
                    return false;
                }
            }
        }
        return true;
    }

    public void checkPermission(PrincipalCollection principals, String permission) throws AuthorizationException {
        assertRealmsConfigured();
        if (!isPermitted(principals, permission)) {
            throw new UnauthorizedException("Subject does not have permission [" + permission + "]");
        }
    }

    public void checkPermission(PrincipalCollection principals, Permission permission) throws AuthorizationException {
        assertRealmsConfigured();
        if (!isPermitted(principals, permission)) {
            throw new UnauthorizedException("Subject does not have permission [" + permission + "]");
        }
    }


    public void checkPermissions(PrincipalCollection principals, String... permissions) throws AuthorizationException {
        assertRealmsConfigured();
        if (permissions != null && permissions.length > 0) {
            for (String perm : permissions) {
                checkPermission(principals, perm);
            }
        }
    }

    public void checkPermissions(PrincipalCollection principals, Collection<Permission> permissions) throws AuthorizationException {
        assertRealmsConfigured();
        if (permissions != null) {
            for (Permission permission : permissions) {
                checkPermission(principals, permission);
            }
        }
    }

    public boolean hasRole(PrincipalCollection principals, String roleIdentifier) {
        assertRealmsConfigured();
        for (Realm realm : getRealms()) {
            if (!(realm instanceof Authorizer)) continue;
            if (((Authorizer) realm).hasRole(principals, roleIdentifier)) {
                return true;
            }
        }
        return false;
    }

    public boolean[] hasRoles(PrincipalCollection principals, List<String> roleIdentifiers) {
        assertRealmsConfigured();
        if (roleIdentifiers != null && !roleIdentifiers.isEmpty()) {
            boolean[] hasRoles = new boolean[roleIdentifiers.size()];
            int i = 0;
            for (String roleId : roleIdentifiers) {
                hasRoles[i++] = hasRole(principals, roleId);
            }
            return hasRoles;
        }

        return new boolean[0];
    }

    public boolean hasAllRoles(PrincipalCollection principals, Collection<String> roleIdentifiers) {
        assertRealmsConfigured();
        for (String roleIdentifier : roleIdentifiers) {
            if (!hasRole(principals, roleIdentifier)) {
                return false;
            }
        }
        return true;
    }

    public void checkRole(PrincipalCollection principals, String role) throws AuthorizationException {
        assertRealmsConfigured();
        if (!hasRole(principals, role)) {
            throw new UnauthorizedException("Subject does not have role [" + role + "]");
        }
    }

    public void checkRoles(PrincipalCollection principals, Collection<String> roles) throws AuthorizationException {
        if (roles != null && !roles.isEmpty()) checkRoles(principals, roles.toArray(new String[roles.size()]));
    }


    public void checkRoles(PrincipalCollection principals, String... roles) throws AuthorizationException {
        assertRealmsConfigured();
        if (roles != null) {
            for (String role : roles) {
                checkRole(principals, role);
            }
        }
    }
}
