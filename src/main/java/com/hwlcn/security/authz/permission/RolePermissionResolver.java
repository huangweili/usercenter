package com.hwlcn.security.authz.permission;

import com.hwlcn.security.authz.Permission;

import java.util.Collection;


public interface RolePermissionResolver {

    Collection<Permission> resolvePermissionsInRole(String roleString);

}
