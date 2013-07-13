package com.hwlcn.security.mgt;

import com.hwlcn.security.session.Session;
import com.hwlcn.security.subject.PrincipalCollection;
import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.subject.support.DefaultSubjectContext;
import com.hwlcn.security.subject.support.DelegatingSubject;
import com.hwlcn.security.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;


public class DefaultSubjectDAO implements SubjectDAO {

    private static final Logger log = LoggerFactory.getLogger(DefaultSubjectDAO.class);

    private SessionStorageEvaluator sessionStorageEvaluator;

    public DefaultSubjectDAO() {
        this.sessionStorageEvaluator = new DefaultSessionStorageEvaluator();
    }

    protected boolean isSessionStorageEnabled(Subject subject) {
        return getSessionStorageEvaluator().isSessionStorageEnabled(subject);
    }

    public SessionStorageEvaluator getSessionStorageEvaluator() {
        return sessionStorageEvaluator;
    }

    public void setSessionStorageEvaluator(SessionStorageEvaluator sessionStorageEvaluator) {
        this.sessionStorageEvaluator = sessionStorageEvaluator;
    }

    public Subject save(Subject subject) {
        if (isSessionStorageEnabled(subject)) {
            saveToSession(subject);
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Session storage of subject state for Subject [{}] has been disabled: identity and " +
                        "authentication state are expected to be initialized on every request or invocation.", subject);
            }
        }

        return subject;
    }


    protected void saveToSession(Subject subject) {
        mergePrincipals(subject);
        mergeAuthenticationState(subject);
    }

    protected void mergePrincipals(Subject subject) {

        PrincipalCollection currentPrincipals = null;

        if (subject.isRunAs() && subject instanceof DelegatingSubject) {
            try {
                Field field = DelegatingSubject.class.getDeclaredField("principals");
                field.setAccessible(true);
                currentPrincipals = (PrincipalCollection) field.get(subject);
            } catch (Exception e) {
                throw new IllegalStateException("Unable to access DelegatingSubject principals property.", e);
            }
        }
        if (currentPrincipals == null || currentPrincipals.isEmpty()) {
            currentPrincipals = subject.getPrincipals();
        }

        Session session = subject.getSession(false);

        if (session == null) {
            if (!CollectionUtils.isEmpty(currentPrincipals)) {
                session = subject.getSession();
                session.setAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY, currentPrincipals);
            }
        } else {
            PrincipalCollection existingPrincipals =
                    (PrincipalCollection) session.getAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY);

            if (CollectionUtils.isEmpty(currentPrincipals)) {
                if (!CollectionUtils.isEmpty(existingPrincipals)) {
                    session.removeAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY);
                }
            } else {
                if (!currentPrincipals.equals(existingPrincipals)) {
                    session.setAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY, currentPrincipals);
                }
            }
        }
    }


    protected void mergeAuthenticationState(Subject subject) {

        Session session = subject.getSession(false);

        if (session == null) {
            if (subject.isAuthenticated()) {
                session = subject.getSession();
                session.setAttribute(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY, Boolean.TRUE);
            }
        } else {
            Boolean existingAuthc = (Boolean) session.getAttribute(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY);

            if (subject.isAuthenticated()) {
                if (existingAuthc == null || !existingAuthc) {
                    session.setAttribute(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY, Boolean.TRUE);
                }
            } else {
                if (existingAuthc != null) {
                    session.removeAttribute(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY);
                }
            }
        }
    }

    protected void removeFromSession(Subject subject) {
        Session session = subject.getSession(false);
        if (session != null) {
            session.removeAttribute(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY);
            session.removeAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY);
        }
    }

    public void delete(Subject subject) {
        removeFromSession(subject);
    }
}
