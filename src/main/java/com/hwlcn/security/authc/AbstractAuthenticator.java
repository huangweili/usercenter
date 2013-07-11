package com.hwlcn.security.authc;

import com.hwlcn.security.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;


public abstract class AbstractAuthenticator implements Authenticator, LogoutAware {

    private static final Logger log = LoggerFactory.getLogger(AbstractAuthenticator.class);

    private Collection<AuthenticationListener> listeners;

    public AbstractAuthenticator() {
        listeners = new ArrayList<AuthenticationListener>();
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public void setAuthenticationListeners(Collection<AuthenticationListener> listeners) {
        if (listeners == null) {
            this.listeners = new ArrayList<AuthenticationListener>();
        } else {
            this.listeners = listeners;
        }
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public Collection<AuthenticationListener> getAuthenticationListeners() {
        return this.listeners;
    }

    protected void notifySuccess(AuthenticationToken token, AuthenticationInfo info) {
        for (AuthenticationListener listener : this.listeners) {
            listener.onSuccess(token, info);
        }
    }

    protected void notifyFailure(AuthenticationToken token, AuthenticationException ae) {
        for (AuthenticationListener listener : this.listeners) {
            listener.onFailure(token, ae);
        }
    }

    protected void notifyLogout(PrincipalCollection principals) {
        for (AuthenticationListener listener : this.listeners) {
            listener.onLogout(principals);
        }
    }

    public void onLogout(PrincipalCollection principals) {
        notifyLogout(principals);
    }

    public final AuthenticationInfo authenticate(AuthenticationToken token) throws AuthenticationException {

        if (token == null) {
            throw new IllegalArgumentException("Method argumet (authentication token) cannot be null.");
        }
        if (log.isTraceEnabled())
            log.trace("Authentication attempt received for token [{}]", token);

        AuthenticationInfo info;
        try {
            info = doAuthenticate(token);
            if (info == null) {
                String msg = "No account information found for authentication token [" + token + "] by this " +
                        "Authenticator instance.  Please check that it is configured correctly.";
                throw new AuthenticationException(msg);
            }
        } catch (Throwable t) {
            AuthenticationException ae = null;
            if (t instanceof AuthenticationException) {
                ae = (AuthenticationException) t;
            }
            if (ae == null) {
                String msg = "Authentication failed for token submission [" + token + "].  Possible unexpected " +
                        "error? (Typical or expected login exceptions should extend from AuthenticationException).";
                ae = new AuthenticationException(msg, t);
            }
            try {
                notifyFailure(token, ae);
            } catch (Throwable t2) {
                if (log.isWarnEnabled()) {
                    String msg = "Unable to send notification for failed authentication attempt - listener error?.  " +
                            "Please check your AuthenticationListener implementation(s).  Logging sending exception " +
                            "and propagating original AuthenticationException instead...";
                    log.warn(msg, t2);
                }
            }


            throw ae;
        }

        log.debug("Authentication successful for token [{}].  Returned account [{}]", token, info);

        notifySuccess(token, info);

        return info;
    }

    protected abstract AuthenticationInfo doAuthenticate(AuthenticationToken token)
            throws AuthenticationException;


}
