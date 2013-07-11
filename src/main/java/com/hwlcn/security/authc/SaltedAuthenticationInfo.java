package com.hwlcn.security.authc;

import com.hwlcn.security.util.ByteSource;

public interface SaltedAuthenticationInfo extends AuthenticationInfo {


    ByteSource getCredentialsSalt();
}
