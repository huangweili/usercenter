package com.hwlcn.security.authz.permission;

import java.io.Serializable;

import com.hwlcn.security.authz.Permission;



public class AllPermission implements Permission, Serializable {

    public boolean implies(Permission p) {
        return true;
    }
}
