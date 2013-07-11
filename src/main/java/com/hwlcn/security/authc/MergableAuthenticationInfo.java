package com.hwlcn.security.authc;

public interface MergableAuthenticationInfo extends AuthenticationInfo {


    void merge(AuthenticationInfo info);

}
