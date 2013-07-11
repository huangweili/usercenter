package com.hwlcn.security.authc;

public interface Authenticator {

    public AuthenticationInfo authenticate(AuthenticationToken authenticationToken)
            throws AuthenticationException;
}
