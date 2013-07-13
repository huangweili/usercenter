package com.hwlcn.security.realm;


import com.hwlcn.security.authc.AuthenticationException;
import com.hwlcn.security.authc.AuthenticationInfo;
import com.hwlcn.security.authc.AuthenticationToken;

public interface Realm {


    String getName();

    boolean supports(AuthenticationToken token);


    AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException;

}
