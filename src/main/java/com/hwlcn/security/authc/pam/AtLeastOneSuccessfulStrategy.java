package com.hwlcn.security.authc.pam;

import com.hwlcn.security.authc.AuthenticationException;
import com.hwlcn.security.authc.AuthenticationInfo;
import com.hwlcn.security.util.CollectionUtils;
import com.hwlcn.security.authc.AuthenticationToken;

public class AtLeastOneSuccessfulStrategy extends AbstractAuthenticationStrategy {

    public AuthenticationInfo afterAllAttempts(AuthenticationToken token, AuthenticationInfo aggregate) throws AuthenticationException {
        if (aggregate == null || CollectionUtils.isEmpty(aggregate.getPrincipals())) {
            throw new AuthenticationException("Authentication token of type [" + token.getClass() + "] " +
                    "could not be authenticated by any configured realms.  Please ensure that at least one realm can " +
                    "authenticate these tokens.");
        }

        return aggregate;
    }
}
