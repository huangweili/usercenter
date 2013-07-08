package com.hwlcn.security.web.mgt;

import com.hwlcn.security.mgt.DefaultSecurityManager;
import com.hwlcn.security.mgt.DefaultSubjectDAO;
import com.hwlcn.security.mgt.SessionStorageEvaluator;
import com.hwlcn.security.mgt.SubjectDAO;
import com.hwlcn.security.realm.Realm;
import com.hwlcn.security.session.mgt.SessionContext;
import com.hwlcn.security.session.mgt.SessionKey;
import com.hwlcn.security.session.mgt.SessionManager;
import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.subject.SubjectContext;
import com.hwlcn.security.web.servlet.SecurityHttpServletRequest;
import com.hwlcn.security.web.session.mgt.*;
import com.hwlcn.security.web.subject.WebSubject;
import com.hwlcn.security.web.subject.WebSubjectContext;
import com.hwlcn.security.web.subject.support.DefaultWebSubjectContext;
import com.hwlcn.security.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.Serializable;
import java.util.Collection;


public class DefaultWebSecurityManager extends DefaultSecurityManager implements WebSecurityManager {

    private static final Logger log = LoggerFactory.getLogger(DefaultWebSecurityManager.class);

    @Deprecated
    public static final String HTTP_SESSION_MODE = "http";
    @Deprecated
    public static final String NATIVE_SESSION_MODE = "native";


    public DefaultWebSecurityManager() {
        super();
        ((DefaultSubjectDAO) this.subjectDAO).setSessionStorageEvaluator(new DefaultWebSessionStorageEvaluator());
        setSubjectFactory(new DefaultWebSubjectFactory());
        setRememberMeManager(new CookieRememberMeManager());
        setSessionManager(new ServletContainerSessionManager());
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public DefaultWebSecurityManager(Realm singleRealm) {
        this();
        setRealm(singleRealm);
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public DefaultWebSecurityManager(Collection<Realm> realms) {
        this();
        setRealms(realms);
    }

    @Override
    protected SubjectContext createSubjectContext() {
        return new DefaultWebSubjectContext();
    }

    @Override
    public void setSubjectDAO(SubjectDAO subjectDAO) {
        super.setSubjectDAO(subjectDAO);
        applySessionManagerToSessionStorageEvaluatorIfPossible();
    }

    @Override
    protected void afterSessionManagerSet() {
        super.afterSessionManagerSet();
        applySessionManagerToSessionStorageEvaluatorIfPossible();
    }

    private void applySessionManagerToSessionStorageEvaluatorIfPossible() {
        SubjectDAO subjectDAO = getSubjectDAO();
        if (subjectDAO instanceof DefaultSubjectDAO) {
            SessionStorageEvaluator evaluator = ((DefaultSubjectDAO) subjectDAO).getSessionStorageEvaluator();
            if (evaluator instanceof DefaultWebSessionStorageEvaluator) {
                ((DefaultWebSessionStorageEvaluator) evaluator).setSessionManager(getSessionManager());
            }
        }
    }

    @Override
    protected SubjectContext copy(SubjectContext subjectContext) {
        if (subjectContext instanceof WebSubjectContext) {
            return new DefaultWebSubjectContext((WebSubjectContext) subjectContext);
        }
        return super.copy(subjectContext);
    }


    @Override
    public void setSessionManager(SessionManager sessionManager) {
        if (sessionManager != null && !(sessionManager instanceof WebSessionManager)) {
            if (log.isWarnEnabled()) {
                String msg = "The " + getClass().getName() + " implementation expects SessionManager instances " +
                        "that implement the " + WebSessionManager.class.getName() + " interface.  The " +
                        "configured instance is of type [" + sessionManager.getClass().getName() + "] which does not " +
                        "implement this interface..  This may cause unexpected behavior.";
                log.warn(msg);
            }
        }
        setInternalSessionManager(sessionManager);
    }

    private void setInternalSessionManager(SessionManager sessionManager) {
        super.setSessionManager(sessionManager);
    }


    public boolean isHttpSessionMode() {
        SessionManager sessionManager = getSessionManager();
        return sessionManager instanceof WebSessionManager && ((WebSessionManager) sessionManager).isServletContainerSessions();
    }

    protected SessionManager createSessionManager(String sessionMode) {
        if (sessionMode == null || !sessionMode.equalsIgnoreCase(NATIVE_SESSION_MODE)) {
            log.info("{} mode - enabling ServletContainerSessionManager (HTTP-only Sessions)", HTTP_SESSION_MODE);
            return new ServletContainerSessionManager();
        } else {
            log.info("{} mode - enabling DefaultWebSessionManager (non-HTTP and HTTP Sessions)", NATIVE_SESSION_MODE);
            return new DefaultWebSessionManager();
        }
    }

    @Override
    protected SessionContext createSessionContext(SubjectContext subjectContext) {
        SessionContext sessionContext = super.createSessionContext(subjectContext);
        if (subjectContext instanceof WebSubjectContext) {
            WebSubjectContext wsc = (WebSubjectContext) subjectContext;
            ServletRequest request = wsc.resolveServletRequest();
            ServletResponse response = wsc.resolveServletResponse();
            DefaultWebSessionContext webSessionContext = new DefaultWebSessionContext(sessionContext);
            if (request != null) {
                webSessionContext.setServletRequest(request);
            }
            if (response != null) {
                webSessionContext.setServletResponse(response);
            }

            sessionContext = webSessionContext;
        }
        return sessionContext;
    }

    @Override
    protected SessionKey getSessionKey(SubjectContext context) {
        if (WebUtils.isWeb(context)) {
            Serializable sessionId = context.getSessionId();
            ServletRequest request = WebUtils.getRequest(context);
            ServletResponse response = WebUtils.getResponse(context);
            return new WebSessionKey(sessionId, request, response);
        } else {
            return super.getSessionKey(context);

        }
    }

    @Override
    protected void beforeLogout(Subject subject) {
        super.beforeLogout(subject);
        removeRequestIdentity(subject);
    }

    protected void removeRequestIdentity(Subject subject) {
        if (subject instanceof WebSubject) {
            WebSubject webSubject = (WebSubject) subject;
            ServletRequest request = webSubject.getServletRequest();
            if (request != null) {
                request.setAttribute(SecurityHttpServletRequest.IDENTITY_REMOVED_KEY, Boolean.TRUE);
            }
        }
    }
}
