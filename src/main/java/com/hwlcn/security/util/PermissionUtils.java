package com.hwlcn.security.util;

import com.hwlcn.security.authz.Permission;
import com.hwlcn.security.authz.permission.PermissionResolver;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;


public class PermissionUtils {

    /**
     * 根据权限的解析类解析字符串权限
     * @param s
     * @param permissionResolver
     * @return
     */
    public static Set<Permission> resolveDelimitedPermissions(String s, PermissionResolver permissionResolver) {
        Set<String> permStrings = toPermissionStrings(s);
        return resolvePermissions(permStrings, permissionResolver);
    }

    public static Set<String> toPermissionStrings(String permissionsString) {
        String[] tokens = StringUtils.split(permissionsString);
        if (tokens != null && tokens.length > 0) {
            return new LinkedHashSet<String>(Arrays.asList(tokens));
        }
        return null;
    }

    public static Set<Permission> resolvePermissions(Collection<String> permissionStrings, PermissionResolver permissionResolver) {
        Set<Permission> permissions = new LinkedHashSet<Permission>(permissionStrings.size());
        for (String permissionString : permissionStrings) {
            permissions.add(permissionResolver.resolvePermission(permissionString));
        }
        return permissions;
    }
}
