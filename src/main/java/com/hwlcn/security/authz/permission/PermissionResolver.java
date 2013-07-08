package com.hwlcn.security.authz.permission;

import com.hwlcn.security.authz.Permission;


public interface PermissionResolver {


    Permission resolvePermission(String permissionString);

}
