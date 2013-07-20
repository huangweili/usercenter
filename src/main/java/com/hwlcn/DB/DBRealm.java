package com.hwlcn.DB;

import com.hwlcn.security.authc.AuthenticationException;
import com.hwlcn.security.authc.AuthenticationInfo;
import com.hwlcn.security.authc.AuthenticationToken;
import com.hwlcn.security.authc.SimpleAuthenticationInfo;
import com.hwlcn.security.authz.AuthorizationInfo;
import com.hwlcn.security.authz.SimpleAuthorizationInfo;
import com.hwlcn.security.realm.AuthorizingRealm;
import com.hwlcn.security.subject.PrincipalCollection;

import java.util.HashSet;
import java.util.Set;

/**
 * User: HuangWeili
 * Date: 13-7-20
 * Time: 下午8:23
 */
public class DBRealm extends AuthorizingRealm {
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        Set<String> roles=new HashSet<String>();
        roles.add("admin");
        return new SimpleAuthorizationInfo(roles);
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

        return new SimpleAuthenticationInfo("hwlchina","hwlchina","hwlchina");
    }
}
