package com.hwlcn.security.authc.pam;

import com.hwlcn.security.authc.AuthenticationException;
import com.hwlcn.security.authc.AuthenticationInfo;
import com.hwlcn.security.authc.AuthenticationToken;
import com.hwlcn.security.realm.Realm;

import java.util.Collection;


public interface AuthenticationStrategy {

    AuthenticationInfo beforeAllAttempts(Collection<? extends Realm> realms, AuthenticationToken token) throws AuthenticationException;

    AuthenticationInfo beforeAttempt(Realm realm, AuthenticationToken token, AuthenticationInfo aggregate) throws AuthenticationException;

    AuthenticationInfo afterAttempt(Realm realm, AuthenticationToken token, AuthenticationInfo singleRealmInfo, AuthenticationInfo aggregateInfo, Throwable t)
            throws AuthenticationException;

    AuthenticationInfo afterAllAttempts(AuthenticationToken token, AuthenticationInfo aggregate) throws AuthenticationException;
}
