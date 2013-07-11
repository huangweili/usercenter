package com.hwlcn.security.authc.pam;

import com.hwlcn.security.authc.AuthenticationException;
import com.hwlcn.security.authc.AuthenticationInfo;
import com.hwlcn.security.authc.AuthenticationToken;
import com.hwlcn.security.authc.UnknownAccountException;
import com.hwlcn.security.realm.Realm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



public class AllSuccessfulStrategy extends AbstractAuthenticationStrategy {

    private static final Logger log = LoggerFactory.getLogger(AllSuccessfulStrategy.class);

    public AuthenticationInfo beforeAttempt(Realm realm, AuthenticationToken token, AuthenticationInfo info) throws AuthenticationException {
        if (!realm.supports(token)) {
            String msg = "Realm [" + realm + "] of type [" + realm.getClass().getName() + "] does not support " +
                    " the submitted AuthenticationToken [" + token + "].  The [" + getClass().getName() +
                    "] implementation requires all configured realm(s) to support and be able to process the submitted " +
                    "AuthenticationToken.";
            throw new UnsupportedTokenException(msg);
        }

        return info;
    }

    public AuthenticationInfo afterAttempt(Realm realm, AuthenticationToken token, AuthenticationInfo info, AuthenticationInfo aggregate, Throwable t)
            throws AuthenticationException {
        if (t != null) {
            if (t instanceof AuthenticationException) {
                throw ((AuthenticationException) t);
            } else {
                String msg = "Unable to acquire account data from realm [" + realm + "].  The [" +
                        getClass().getName() + " implementation requires all configured realm(s) to operate successfully " +
                        "for a successful authentication.";
                throw new AuthenticationException(msg, t);
            }
        }
        if (info == null) {
            String msg = "Realm [" + realm + "] could not find any associated account data for the submitted " +
                    "AuthenticationToken [" + token + "].  The [" + getClass().getName() + "] implementation requires " +
                    "all configured realm(s) to acquire valid account data for a submitted token during the " +
                    "log-in process.";
            throw new UnknownAccountException(msg);
        }

        log.debug("Account successfully authenticated using realm [{}]", realm);
        merge(info, aggregate);
        return aggregate;
    }
}
