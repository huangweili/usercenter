package com.hwlcn.security.mgt;

import com.hwlcn.security.authz.AuthorizationException;
import com.hwlcn.security.authz.ModularRealmAuthorizer;
import com.hwlcn.security.authz.Permission;
import com.hwlcn.security.util.LifecycleUtils;
import com.hwlcn.security.authz.Authorizer;
import com.hwlcn.security.subject.PrincipalCollection;

import java.util.Collection;
import java.util.List;


public abstract class AuthorizingSecurityManager extends AuthenticatingSecurityManager {

    private Authorizer authorizer;

    public AuthorizingSecurityManager() {
        super();
        this.authorizer = new ModularRealmAuthorizer();
    }

    public Authorizer getAuthorizer() {
        return authorizer;
    }

    public void setAuthorizer(Authorizer authorizer) {
        if (authorizer == null) {
            String msg = "Authorizer argument cannot be null.";
            throw new IllegalArgumentException(msg);
        }
        this.authorizer = authorizer;
    }

    protected void afterRealmsSet() {
        super.afterRealmsSet();
        if (this.authorizer instanceof ModularRealmAuthorizer) {
            ((ModularRealmAuthorizer) this.authorizer).setRealms(getRealms());
        }
    }

    public void destroy() {
        LifecycleUtils.destroy(getAuthorizer());
        this.authorizer = null;
        super.destroy();
    }

    public boolean isPermitted(PrincipalCollection principals, String permissionString) {
        return this.authorizer.isPermitted(principals, permissionString);
    }

    public boolean isPermitted(PrincipalCollection principals, Permission permission) {
        return this.authorizer.isPermitted(principals, permission);
    }

    public boolean[] isPermitted(PrincipalCollection principals, String... permissions) {
        return this.authorizer.isPermitted(principals, permissions);
    }

    public boolean[] isPermitted(PrincipalCollection principals, List<Permission> permissions) {
        return this.authorizer.isPermitted(principals, permissions);
    }

    public boolean isPermittedAll(PrincipalCollection principals, String... permissions) {
        return this.authorizer.isPermittedAll(principals, permissions);
    }

    public boolean isPermittedAll(PrincipalCollection principals, Collection<Permission> permissions) {
        return this.authorizer.isPermittedAll(principals, permissions);
    }

    public void checkPermission(PrincipalCollection principals, String permission) throws AuthorizationException {
        this.authorizer.checkPermission(principals, permission);
    }

    public void checkPermission(PrincipalCollection principals, Permission permission) throws AuthorizationException {
        this.authorizer.checkPermission(principals, permission);
    }

    public void checkPermissions(PrincipalCollection principals, String... permissions) throws AuthorizationException {
        this.authorizer.checkPermissions(principals, permissions);
    }

    public void checkPermissions(PrincipalCollection principals, Collection<Permission> permissions) throws AuthorizationException {
        this.authorizer.checkPermissions(principals, permissions);
    }

    public boolean hasRole(PrincipalCollection principals, String roleIdentifier) {
        return this.authorizer.hasRole(principals, roleIdentifier);
    }

    public boolean[] hasRoles(PrincipalCollection principals, List<String> roleIdentifiers) {
        return this.authorizer.hasRoles(principals, roleIdentifiers);
    }

    public boolean hasAllRoles(PrincipalCollection principals, Collection<String> roleIdentifiers) {
        return this.authorizer.hasAllRoles(principals, roleIdentifiers);
    }

    public void checkRole(PrincipalCollection principals, String role) throws AuthorizationException {
        this.authorizer.checkRole(principals, role);
    }

    public void checkRoles(PrincipalCollection principals, Collection<String> roles) throws AuthorizationException {
        this.authorizer.checkRoles(principals, roles);
    }
    
    public void checkRoles(PrincipalCollection principals, String... roles) throws AuthorizationException {
        this.authorizer.checkRoles(principals, roles);
    }    
}
