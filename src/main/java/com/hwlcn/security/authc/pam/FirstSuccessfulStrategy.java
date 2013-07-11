package com.hwlcn.security.authc.pam;

import com.hwlcn.security.authc.AuthenticationException;
import com.hwlcn.security.authc.AuthenticationInfo;
import com.hwlcn.security.authc.AuthenticationToken;
import com.hwlcn.security.util.CollectionUtils;
import com.hwlcn.security.realm.Realm;

import java.util.Collection;


public class FirstSuccessfulStrategy extends AbstractAuthenticationStrategy {

    public AuthenticationInfo beforeAllAttempts(Collection<? extends Realm> realms, AuthenticationToken token) throws AuthenticationException {
        return null;
    }

    protected AuthenticationInfo merge(AuthenticationInfo info, AuthenticationInfo aggregate) {
        if (aggregate != null && !CollectionUtils.isEmpty(aggregate.getPrincipals())) {
            return aggregate;
        }
        return info != null ? info : aggregate;
    }
}
