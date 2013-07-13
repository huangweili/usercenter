package com.hwlcn.security.mgt;

import com.hwlcn.security.authc.*;
import com.hwlcn.security.realm.Realm;
import com.hwlcn.security.session.InvalidSessionException;
import com.hwlcn.security.session.Session;
import com.hwlcn.security.session.mgt.DefaultSessionContext;
import com.hwlcn.security.session.mgt.DefaultSessionKey;
import com.hwlcn.security.session.mgt.SessionContext;
import com.hwlcn.security.session.mgt.SessionKey;
import com.hwlcn.security.subject.PrincipalCollection;
import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.subject.SubjectContext;
import com.hwlcn.security.subject.support.DefaultSubjectContext;
import com.hwlcn.security.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.Collection;


public class DefaultSecurityManager extends SessionsSecurityManager {

    private static final Logger log = LoggerFactory.getLogger(DefaultSecurityManager.class);

    protected RememberMeManager rememberMeManager;
    protected SubjectDAO subjectDAO;
    protected SubjectFactory subjectFactory;

    public DefaultSecurityManager() {
        super();
        this.subjectFactory = new DefaultSubjectFactory();
        this.subjectDAO = new DefaultSubjectDAO();
    }

    public DefaultSecurityManager(Realm singleRealm) {
        this();
        setRealm(singleRealm);
    }

    public DefaultSecurityManager(Collection<Realm> realms) {
        this();
        setRealms(realms);
    }

    public SubjectFactory getSubjectFactory() {
        return subjectFactory;
    }

    public void setSubjectFactory(SubjectFactory subjectFactory) {
        this.subjectFactory = subjectFactory;
    }

    public SubjectDAO getSubjectDAO() {
        return subjectDAO;
    }

    public void setSubjectDAO(SubjectDAO subjectDAO) {
        this.subjectDAO = subjectDAO;
    }

    public RememberMeManager getRememberMeManager() {
        return rememberMeManager;
    }

    public void setRememberMeManager(RememberMeManager rememberMeManager) {
        this.rememberMeManager = rememberMeManager;
    }

    protected SubjectContext createSubjectContext() {
        return new DefaultSubjectContext();
    }

    protected Subject createSubject(AuthenticationToken token, AuthenticationInfo info, Subject existing) {
        SubjectContext context = createSubjectContext();
        context.setAuthenticated(true);
        context.setAuthenticationToken(token);
        context.setAuthenticationInfo(info);
        if (existing != null) {
            context.setSubject(existing);
        }
        return createSubject(context);
    }


    protected void rememberMeSuccessfulLogin(AuthenticationToken token, AuthenticationInfo info, Subject subject) {
        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                rmm.onSuccessfulLogin(subject, token, info);
            } catch (Exception e) {
                if (log.isWarnEnabled()) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                            "] threw an exception during onSuccessfulLogin.  RememberMe services will not be " +
                            "performed for account [" + info + "].";
                    log.warn(msg, e);
                }
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("This " + getClass().getName() + " instance does not have a " +
                        "[" + RememberMeManager.class.getName() + "] instance configured.  RememberMe services " +
                        "will not be performed for account [" + info + "].");
            }
        }
    }

    protected void rememberMeFailedLogin(AuthenticationToken token, AuthenticationException ex, Subject subject) {
        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                rmm.onFailedLogin(subject, token, ex);
            } catch (Exception e) {
                if (log.isWarnEnabled()) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                            "] threw an exception during onFailedLogin for AuthenticationToken [" +
                            token + "].";
                    log.warn(msg, e);
                }
            }
        }
    }

    protected void rememberMeLogout(Subject subject) {
        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                rmm.onLogout(subject);
            } catch (Exception e) {
                if (log.isWarnEnabled()) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                            "] threw an exception during onLogout for subject with principals [" +
                            (subject != null ? subject.getPrincipals() : null) + "]";
                    log.warn(msg, e);
                }
            }
        }
    }


    public Subject login(Subject subject, AuthenticationToken token) throws AuthenticationException {
        AuthenticationInfo info;
        try {
            info = authenticate(token);
        } catch (AuthenticationException ae) {
            try {
                onFailedLogin(token, ae, subject);
            } catch (Exception e) {
                if (log.isInfoEnabled()) {
                    log.info("onFailedLogin method threw an " +
                            "exception.  Logging and propagating original AuthenticationException.", e);
                }
            }
            throw ae;
        }

        Subject loggedIn = createSubject(token, info, subject);

        onSuccessfulLogin(token, info, loggedIn);

        return loggedIn;
    }

    protected void onSuccessfulLogin(AuthenticationToken token, AuthenticationInfo info, Subject subject) {
        rememberMeSuccessfulLogin(token, info, subject);
    }

    protected void onFailedLogin(AuthenticationToken token, AuthenticationException ae, Subject subject) {
        rememberMeFailedLogin(token, ae, subject);
    }

    protected void beforeLogout(Subject subject) {
        rememberMeLogout(subject);
    }

    protected SubjectContext copy(SubjectContext subjectContext) {
        return new DefaultSubjectContext(subjectContext);
    }


    public Subject createSubject(SubjectContext subjectContext) {
        SubjectContext context = copy(subjectContext);

        context = ensureSecurityManager(context);

        context = resolveSession(context);

        context = resolvePrincipals(context);

        Subject subject = doCreateSubject(context);
        save(subject);

        return subject;
    }


    protected Subject doCreateSubject(SubjectContext context) {
        return getSubjectFactory().createSubject(context);
    }

    protected void save(Subject subject) {
        this.subjectDAO.save(subject);
    }

    protected void delete(Subject subject) {
        this.subjectDAO.delete(subject);
    }

    @SuppressWarnings({"unchecked"})
    protected SubjectContext ensureSecurityManager(SubjectContext context) {
        if (context.resolveSecurityManager() != null) {
            if (log.isTraceEnabled()) {
                log.trace("Context already contains a SecurityManager instance.  Returning.");
            }
            return context;
        }
        if (log.isTraceEnabled()) {
            log.trace("No SecurityManager found in context.  Adding self reference.");
        }
        context.setSecurityManager(this);
        return context;
    }


    @SuppressWarnings({"unchecked"})
    protected SubjectContext resolveSession(SubjectContext context) {
        if (context.resolveSession() != null) {
            if (log.isDebugEnabled()) {
                log.debug("Context already contains a session.  Returning.");
            }

            return context;
        }
        try {
            Session session = resolveContextSession(context);
            if (session != null) {
                context.setSession(session);
            }
        } catch (InvalidSessionException e) {
            if (log.isDebugEnabled()) {
                log.debug("Resolved SubjectContext context session is invalid.  Ignoring and creating an anonymous " +
                        "(session-less) Subject instance.", e);
            }
        }
        return context;
    }

    protected Session resolveContextSession(SubjectContext context) throws InvalidSessionException {
        SessionKey key = getSessionKey(context);
        if (key != null) {
            return getSession(key);
        }
        return null;
    }

    protected SessionKey getSessionKey(SubjectContext context) {
        Serializable sessionId = context.getSessionId();
        if (sessionId != null) {
            return new DefaultSessionKey(sessionId);
        }
        return null;
    }


    @SuppressWarnings({"unchecked"})
    protected SubjectContext resolvePrincipals(SubjectContext context) {

        PrincipalCollection principals = context.resolvePrincipals();

        if (CollectionUtils.isEmpty(principals)) {
            if (log.isTraceEnabled()) {
                log.trace("No identity (PrincipalCollection) found in the context.  Looking for a remembered identity.");
            }
            principals = getRememberedIdentity(context);

            if (!CollectionUtils.isEmpty(principals)) {
                if (log.isDebugEnabled()) {
                    log.debug("Found remembered PrincipalCollection.  Adding to the context to be used " +
                            "for subject construction by the SubjectFactory.");
                }
                context.setPrincipals(principals);


            } else {
                if (log.isTraceEnabled()) {
                    log.trace("No remembered identity found.  Returning original context.");
                }
            }
        }

        return context;
    }

    protected SessionContext createSessionContext(SubjectContext subjectContext) {
        DefaultSessionContext sessionContext = new DefaultSessionContext();
        if (!CollectionUtils.isEmpty(subjectContext)) {
            sessionContext.putAll(subjectContext);
        }
        Serializable sessionId = subjectContext.getSessionId();
        if (sessionId != null) {
            sessionContext.setSessionId(sessionId);
        }
        String host = subjectContext.resolveHost();
        if (host != null) {
            sessionContext.setHost(host);
        }
        return sessionContext;
    }

    public void logout(Subject subject) {

        if (subject == null) {
            throw new IllegalArgumentException("Subject method argument cannot be null.");
        }

        beforeLogout(subject);

        PrincipalCollection principals = subject.getPrincipals();
        if (principals != null && !principals.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Logging out subject with primary principal {}", principals.getPrimaryPrincipal());
            }
            Authenticator authc = getAuthenticator();
            if (authc instanceof LogoutAware) {
                ((LogoutAware) authc).onLogout(principals);
            }
        }

        try {
            delete(subject);
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                String msg = "Unable to cleanly unbind Subject.  Ignoring (logging out).";
                log.debug(msg, e);
            }
        } finally {
            try {
                stopSession(subject);
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    String msg = "Unable to cleanly stop Session for Subject [" + subject.getPrincipal() + "] " +
                            "Ignoring (logging out).";
                    log.debug(msg, e);
                }
            }
        }
    }

    protected void stopSession(Subject subject) {
        Session s = subject.getSession(false);
        if (s != null) {
            s.stop();
        }
    }


    protected PrincipalCollection getRememberedIdentity(SubjectContext subjectContext) {
        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                return rmm.getRememberedPrincipals(subjectContext);
            } catch (Exception e) {
                if (log.isWarnEnabled()) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                            "] threw an exception during getRememberedPrincipals().";
                    log.warn(msg, e);
                }
            }
        }
        return null;
    }
}
