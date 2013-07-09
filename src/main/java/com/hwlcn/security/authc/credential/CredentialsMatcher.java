package com.hwlcn.security.authc.credential;

import com.hwlcn.security.authc.AuthenticationInfo;
import com.hwlcn.security.authc.AuthenticationToken;



public interface CredentialsMatcher {

    boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info);

}