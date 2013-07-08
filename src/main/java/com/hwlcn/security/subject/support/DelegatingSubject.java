package com.hwlcn.security.subject.support;

import com.hwlcn.security.authc.AuthenticationException;
import com.hwlcn.security.authc.AuthenticationToken;
import com.hwlcn.security.authc.HostAuthenticationToken;
import com.hwlcn.security.authz.AuthorizationException;
import com.hwlcn.security.authz.Permission;
import com.hwlcn.security.authz.UnauthenticatedException;
import com.hwlcn.security.mgt.SecurityManager;
import com.hwlcn.security.session.InvalidSessionException;
import com.hwlcn.security.session.ProxiedSession;
import com.hwlcn.security.session.Session;
import com.hwlcn.security.session.SessionException;
import com.hwlcn.security.session.mgt.DefaultSessionContext;
import com.hwlcn.security.session.mgt.SessionContext;
import com.hwlcn.security.subject.ExecutionException;
import com.hwlcn.security.subject.PrincipalCollection;
import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.subject.SubjectBuilder;
import com.hwlcn.security.util.CollectionUtils;
import com.hwlcn.security.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;

public class DelegatingSubject implements Subject {

    private static final Logger log = LoggerFactory.getLogger(DelegatingSubject.class);

    private static final String RUN_AS_PRINCIPALS_SESSION_KEY =
            DelegatingSubject.class.getName() + ".RUN_AS_PRINCIPALS_SESSION_KEY";

    protected PrincipalCollection principals;
    protected boolean authenticated;
    protected String host;
    protected Session session;
    protected boolean sessionCreationEnabled;

    protected transient SecurityManager securityManager;

    public DelegatingSubject(SecurityManager securityManager) {
        this(null, false, null, null, securityManager);
    }

    public DelegatingSubject(PrincipalCollection principals, boolean authenticated, String host,
                             Session session, SecurityManager securityManager) {
        this(principals, authenticated, host, session, true, securityManager);
    }

    public DelegatingSubject(PrincipalCollection principals, boolean authenticated, String host,
                             Session session, boolean sessionCreationEnabled, SecurityManager securityManager) {
        if (securityManager == null) {
            throw new IllegalArgumentException("SecurityManager argument cannot be null.");
        }
        this.securityManager = securityManager;
        this.principals = principals;
        this.authenticated = authenticated;
        this.host = host;
        if (session != null) {
            this.session = decorate(session);
        }
        this.sessionCreationEnabled = sessionCreationEnabled;
    }

    protected Session decorate(Session session) {
        if (session == null) {
            throw new IllegalArgumentException("session cannot be null");
        }
        return new StoppingAwareProxiedSession(session, this);
    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    protected boolean hasPrincipals() {
        return !CollectionUtils.isEmpty(getPrincipals());
    }

    public String getHost() {
        return this.host;
    }

    private Object getPrimaryPrincipal(PrincipalCollection principals) {
        if (!CollectionUtils.isEmpty(principals)) {
            return principals.getPrimaryPrincipal();
        }
        return null;
    }

    public Object getPrincipal() {
        return getPrimaryPrincipal(getPrincipals());
    }

    public PrincipalCollection getPrincipals() {
        List<PrincipalCollection> runAsPrincipals = getRunAsPrincipalsStack();
        return CollectionUtils.isEmpty(runAsPrincipals) ? this.principals : runAsPrincipals.get(0);
    }

    public boolean isPermitted(String permission) {
        return hasPrincipals() && securityManager.isPermitted(getPrincipals(), permission);
    }

    public boolean isPermitted(Permission permission) {
        return hasPrincipals() && securityManager.isPermitted(getPrincipals(), permission);
    }

    public boolean[] isPermitted(String... permissions) {
        if (hasPrincipals()) {
            return securityManager.isPermitted(getPrincipals(), permissions);
        } else {
            return new boolean[permissions.length];
        }
    }

    public boolean[] isPermitted(List<Permission> permissions) {
        if (hasPrincipals()) {
            return securityManager.isPermitted(getPrincipals(), permissions);
        } else {
            return new boolean[permissions.size()];
        }
    }

    public boolean isPermittedAll(String... permissions) {
        return hasPrincipals() && securityManager.isPermittedAll(getPrincipals(), permissions);
    }

    public boolean isPermittedAll(Collection<Permission> permissions) {
        return hasPrincipals() && securityManager.isPermittedAll(getPrincipals(), permissions);
    }

    protected void assertAuthzCheckPossible() throws AuthorizationException {
        if (!hasPrincipals()) {
            String msg = "This subject is anonymous - it does not have any identifying principals and " +
                    "authorization operations require an identity to check against.  A Subject instance will " +
                    "acquire these identifying principals automatically after a successful login is performed " +
                    "be executing " + Subject.class.getName() + ".login(AuthenticationToken) or when 'Remember Me' " +
                    "functionality is enabled by the SecurityManager.  This exception can also occur when a " +
                    "previously logged-in Subject has logged out which " +
                    "makes it anonymous again.  Because an identity is currently not known due to any of these " +
                    "conditions, authorization is denied.";
            throw new UnauthenticatedException(msg);
        }
    }

    public void checkPermission(String permission) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkPermission(getPrincipals(), permission);
    }

    public void checkPermission(Permission permission) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkPermission(getPrincipals(), permission);
    }

    public void checkPermissions(String... permissions) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkPermissions(getPrincipals(), permissions);
    }

    public void checkPermissions(Collection<Permission> permissions) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkPermissions(getPrincipals(), permissions);
    }

    public boolean hasRole(String roleIdentifier) {
        return hasPrincipals() && securityManager.hasRole(getPrincipals(), roleIdentifier);
    }

    public boolean[] hasRoles(List<String> roleIdentifiers) {
        if (hasPrincipals()) {
            return securityManager.hasRoles(getPrincipals(), roleIdentifiers);
        } else {
            return new boolean[roleIdentifiers.size()];
        }
    }

    public boolean hasAllRoles(Collection<String> roleIdentifiers) {
        return hasPrincipals() && securityManager.hasAllRoles(getPrincipals(), roleIdentifiers);
    }

    public void checkRole(String role) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkRole(getPrincipals(), role);
    }

    public void checkRoles(String... roleIdentifiers) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkRoles(getPrincipals(), roleIdentifiers);
    }

    public void checkRoles(Collection<String> roles) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkRoles(getPrincipals(), roles);
    }

    public void login(AuthenticationToken token) throws AuthenticationException {
        clearRunAsIdentitiesInternal();
        Subject subject = securityManager.login(this, token);

        PrincipalCollection principals;

        String host = null;

        if (subject instanceof DelegatingSubject) {
            DelegatingSubject delegating = (DelegatingSubject) subject;
            principals = delegating.principals;
            host = delegating.host;
        } else {
            principals = subject.getPrincipals();
        }

        if (principals == null || principals.isEmpty()) {
            String msg = "Principals returned from securityManager.login( token ) returned a null or " +
                    "empty value.  This value must be non null and populated with one or more elements.";
            throw new IllegalStateException(msg);
        }
        this.principals = principals;
        this.authenticated = true;
        if (token instanceof HostAuthenticationToken) {
            host = ((HostAuthenticationToken) token).getHost();
        }
        if (host != null) {
            this.host = host;
        }
        Session session = subject.getSession(false);
        if (session != null) {
            this.session = decorate(session);
        } else {
            this.session = null;
        }
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public boolean isRemembered() {
        PrincipalCollection principals = getPrincipals();
        return principals != null && !principals.isEmpty() && !isAuthenticated();
    }

    /**
     * Returns {@code true} if this Subject is allowed to create sessions, {@code false} otherwise.
     *
     * @return {@code true} if this Subject is allowed to create sessions, {@code false} otherwise.
     * @since 1.2
     */
    protected boolean isSessionCreationEnabled() {
        return this.sessionCreationEnabled;
    }

    public Session getSession() {
        return getSession(true);
    }

    public Session getSession(boolean create) {
        if (log.isTraceEnabled()) {
            log.trace("attempting to get session; create = " + create +
                    "; session is null = " + (this.session == null) +
                    "; session has id = " + (this.session != null && session.getId() != null));
        }

        if (this.session == null && create) {

            //added in 1.2:
            if (!isSessionCreationEnabled()) {
                String msg = "Session creation has been disabled for the current subject.  This exception indicates " +
                        "that there is either a programming error (using a session when it should never be " +
                        "used) or that Shiro's configuration needs to be adjusted to allow Sessions to be created " +
                        "for the current Subject.  See the " + DisabledSessionException.class.getName() + " JavaDoc " +
                        "for more.";
                throw new DisabledSessionException(msg);
            }

            log.trace("Starting session for host {}", getHost());
            SessionContext sessionContext = createSessionContext();
            Session session = this.securityManager.start(sessionContext);
            this.session = decorate(session);
        }
        return this.session;
    }

    protected SessionContext createSessionContext() {
        SessionContext sessionContext = new DefaultSessionContext();
        if (StringUtils.hasText(host)) {
            sessionContext.setHost(host);
        }
        return sessionContext;
    }

    private void clearRunAsIdentitiesInternal() {
        //try/catch added for SHIRO-298
        try {
            clearRunAsIdentities();
        } catch (SessionException se) {
            log.debug("Encountered session exception trying to clear 'runAs' identities during logout.  This " +
                    "can generally safely be ignored.", se);
        }
    }

    public void logout() {
        try {
            clearRunAsIdentitiesInternal();
            this.securityManager.logout(this);
        } finally {
            this.session = null;
            this.principals = null;
            this.authenticated = false;
        }
    }

    private void sessionStopped() {
        this.session = null;
    }

    public <V> V execute(Callable<V> callable) throws ExecutionException {
        Callable<V> associated = associateWith(callable);
        try {
            return associated.call();
        } catch (Throwable t) {
            throw new ExecutionException(t);
        }
    }

    public void execute(Runnable runnable) {
        Runnable associated = associateWith(runnable);
        associated.run();
    }

    public <V> Callable<V> associateWith(Callable<V> callable) {
        return new SubjectCallable<V>(this, callable);
    }

    public Runnable associateWith(Runnable runnable) {
        if (runnable instanceof Thread) {
            String msg = "This implementation does not support Thread arguments because of JDK ThreadLocal " +
                    "inheritance mechanisms required by Security.  Instead, the method argument should be a non-Thread " +
                    "Runnable and the return value from this method can then be given to an ExecutorService or " +
                    "another Thread.";
            throw new UnsupportedOperationException(msg);
        }
        return new SubjectRunnable(this, runnable);
    }

    private class StoppingAwareProxiedSession extends ProxiedSession {

        private final DelegatingSubject owner;

        private StoppingAwareProxiedSession(Session target, DelegatingSubject owningSubject) {
            super(target);
            owner = owningSubject;
        }

        public void stop() throws InvalidSessionException {
            super.stop();
            owner.sessionStopped();
        }
    }


    public void runAs(PrincipalCollection principals) {
        if (!hasPrincipals()) {
            String msg = "This subject does not yet have an identity.  Assuming the identity of another " +
                    "Subject is only allowed for Subjects with an existing identity.  Try logging this subject in " +
                    "first, or using the " + SubjectBuilder.class.getName() + " to build ad hoc Subject instances " +
                    "with identities as necessary.";
            throw new IllegalStateException(msg);
        }
        pushIdentity(principals);
    }

    public boolean isRunAs() {
        List<PrincipalCollection> stack = getRunAsPrincipalsStack();
        return !CollectionUtils.isEmpty(stack);
    }

    public PrincipalCollection getPreviousPrincipals() {
        PrincipalCollection previousPrincipals = null;
        List<PrincipalCollection> stack = getRunAsPrincipalsStack();
        int stackSize = stack != null ? stack.size() : 0;
        if (stackSize > 0) {
            if (stackSize == 1) {
                previousPrincipals = this.principals;
            } else {
                assert stack != null;
                previousPrincipals = stack.get(1);
            }
        }
        return previousPrincipals;
    }

    public PrincipalCollection releaseRunAs() {
        return popIdentity();
    }

    private List<PrincipalCollection> getRunAsPrincipalsStack() {
        Session session = getSession(false);
        if (session != null) {
            return (List<PrincipalCollection>) session.getAttribute(RUN_AS_PRINCIPALS_SESSION_KEY);
        }
        return null;
    }

    private void clearRunAsIdentities() {
        Session session = getSession(false);
        if (session != null) {
            session.removeAttribute(RUN_AS_PRINCIPALS_SESSION_KEY);
        }
    }

    private void pushIdentity(PrincipalCollection principals) throws NullPointerException {
        if (CollectionUtils.isEmpty(principals)) {
            String msg = "Specified Subject principals cannot be null or empty for 'run as' functionality.";
            throw new NullPointerException(msg);
        }
        List<PrincipalCollection> stack = getRunAsPrincipalsStack();
        if (stack == null) {
            stack = new CopyOnWriteArrayList<PrincipalCollection>();
        }
        stack.add(0, principals);
        Session session = getSession();
        session.setAttribute(RUN_AS_PRINCIPALS_SESSION_KEY, stack);
    }

    private PrincipalCollection popIdentity() {
        PrincipalCollection popped = null;

        List<PrincipalCollection> stack = getRunAsPrincipalsStack();
        if (!CollectionUtils.isEmpty(stack)) {
            popped = stack.remove(0);
            Session session;
            if (!CollectionUtils.isEmpty(stack)) {
                session = getSession();
                session.setAttribute(RUN_AS_PRINCIPALS_SESSION_KEY, stack);
            } else {
                clearRunAsIdentities();
            }
        }

        return popped;
    }
}
