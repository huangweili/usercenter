package com.hwlcn.domain.entity;

/**
 * User: HuangWeili
 * Date: 13-7-20
 * Time: 下午10:23
 */
public class Permission implements com.hwlcn.security.authz.Permission {
    @Override
    public boolean implies(com.hwlcn.security.authz.Permission p) {
        return true;
    }
}
