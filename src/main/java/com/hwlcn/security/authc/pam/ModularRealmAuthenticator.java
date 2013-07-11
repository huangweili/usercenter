package com.hwlcn.security.authc.pam;

import com.hwlcn.security.authc.*;
import com.hwlcn.security.realm.Realm;
import com.hwlcn.security.util.CollectionUtils;
import com.hwlcn.security.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;


public class ModularRealmAuthenticator extends AbstractAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(ModularRealmAuthenticator.class);

    private Collection<Realm> realms;

    private AuthenticationStrategy authenticationStrategy;

    public ModularRealmAuthenticator() {
        this.authenticationStrategy = new AtLeastOneSuccessfulStrategy();
    }

    public void setRealms(Collection<Realm> realms) {
        this.realms = realms;
    }

    protected Collection<Realm> getRealms() {
        return this.realms;
    }

    public AuthenticationStrategy getAuthenticationStrategy() {
        return authenticationStrategy;
    }

    public void setAuthenticationStrategy(AuthenticationStrategy authenticationStrategy) {
        this.authenticationStrategy = authenticationStrategy;
    }


    protected void assertRealmsConfigured() throws IllegalStateException {
        Collection<Realm> realms = getRealms();
        if (CollectionUtils.isEmpty(realms)) {
            String msg = "Configuration error:  No realms have been configured!  One or more realms must be " +
                    "present to execute an authentication attempt.";
            throw new IllegalStateException(msg);
        }
    }

    protected AuthenticationInfo doSingleRealmAuthentication(Realm realm, AuthenticationToken token) {
        if (!realm.supports(token)) {
            String msg = "Realm [" + realm + "] does not support authentication token [" +
                    token + "].  Please ensure that the appropriate Realm implementation is " +
                    "configured correctly or that the realm accepts AuthenticationTokens of this type.";
            throw new UnsupportedTokenException(msg);
        }
        AuthenticationInfo info = realm.getAuthenticationInfo(token);
        if (info == null) {
            String msg = "Realm [" + realm + "] was unable to find account data for the " +
                    "submitted AuthenticationToken [" + token + "].";
            throw new UnknownAccountException(msg);
        }
        return info;
    }

    protected AuthenticationInfo doMultiRealmAuthentication(Collection<Realm> realms, AuthenticationToken token) {

        AuthenticationStrategy strategy = getAuthenticationStrategy();

        AuthenticationInfo aggregate = strategy.beforeAllAttempts(realms, token);

        if (log.isTraceEnabled()) {
            log.trace("Iterating through {} realms for PAM authentication", realms.size());
        }

        for (Realm realm : realms) {

            aggregate = strategy.beforeAttempt(realm, token, aggregate);

            if (realm.supports(token)) {

                log.trace("Attempting to authenticate token [{}] using realm [{}]", token, realm);

                AuthenticationInfo info = null;
                Throwable t = null;
                try {
                    info = realm.getAuthenticationInfo(token);
                } catch (Throwable throwable) {
                    t = throwable;
                    if (log.isDebugEnabled()) {
                        String msg = "Realm [" + realm + "] threw an exception during a multi-realm authentication attempt:";
                        log.debug(msg, t);
                    }
                }

                aggregate = strategy.afterAttempt(realm, token, info, aggregate, t);

            } else {
                log.debug("Realm [{}] does not support token {}.  Skipping realm.", realm, token);
            }
        }

        aggregate = strategy.afterAllAttempts(token, aggregate);

        return aggregate;
    }

    protected AuthenticationInfo doAuthenticate(AuthenticationToken authenticationToken) throws AuthenticationException {
        assertRealmsConfigured();
        Collection<Realm> realms = getRealms();
        if (realms.size() == 1) {
            return doSingleRealmAuthentication(realms.iterator().next(), authenticationToken);
        } else {
            return doMultiRealmAuthentication(realms, authenticationToken);
        }
    }

    public void onLogout(PrincipalCollection principals) {
        super.onLogout(principals);
        Collection<Realm> realms = getRealms();
        if (!CollectionUtils.isEmpty(realms)) {
            for (Realm realm : realms) {
                if (realm instanceof LogoutAware) {
                    ((LogoutAware) realm).onLogout(principals);
                }
            }
        }
    }
}
