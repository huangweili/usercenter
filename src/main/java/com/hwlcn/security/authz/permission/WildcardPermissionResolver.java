package com.hwlcn.security.authz.permission;

import com.hwlcn.security.authz.Permission;


public class WildcardPermissionResolver implements PermissionResolver {

    public Permission resolvePermission(String permissionString) {
        return new WildcardPermission(permissionString);
    }
}
