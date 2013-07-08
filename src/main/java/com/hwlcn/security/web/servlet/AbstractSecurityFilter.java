package com.hwlcn.security.web.servlet;

import com.hwlcn.security.SecurityUtils;
import com.hwlcn.security.session.Session;
import com.hwlcn.security.subject.ExecutionException;
import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.web.filter.mgt.FilterChainResolver;
import com.hwlcn.security.web.mgt.DefaultWebSecurityManager;
import com.hwlcn.security.web.mgt.WebSecurityManager;
import com.hwlcn.security.web.subject.WebSubject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.concurrent.Callable;

public abstract class AbstractSecurityFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(AbstractSecurityFilter.class);

    private static final String STATIC_INIT_PARAM_NAME = "staticSecurityManagerEnabled";

    private WebSecurityManager securityManager;

    private FilterChainResolver filterChainResolver;

    private boolean staticSecurityManagerEnabled;

    protected AbstractSecurityFilter() {
        this.staticSecurityManagerEnabled = false;
    }

    public WebSecurityManager getSecurityManager() {
        return securityManager;
    }

    public void setSecurityManager(WebSecurityManager sm) {
        this.securityManager = sm;
    }

    public FilterChainResolver getFilterChainResolver() {
        return filterChainResolver;
    }

    public void setFilterChainResolver(FilterChainResolver filterChainResolver) {
        this.filterChainResolver = filterChainResolver;
    }

    public boolean isStaticSecurityManagerEnabled() {
        return staticSecurityManagerEnabled;
    }

    public void setStaticSecurityManagerEnabled(boolean staticSecurityManagerEnabled) {
        this.staticSecurityManagerEnabled = staticSecurityManagerEnabled;
    }

    protected final void onFilterConfigSet() throws Exception {

        applyStaticSecurityManagerEnabledConfig();
        init();
        ensureSecurityManager();
        if (isStaticSecurityManagerEnabled()) {
            SecurityUtils.setSecurityManager(getSecurityManager());
        }
    }

    private void applyStaticSecurityManagerEnabledConfig() {
        String value = getInitParam(STATIC_INIT_PARAM_NAME);
        if (value != null) {
            Boolean b = Boolean.valueOf(value);
            if (b != null) {
                setStaticSecurityManagerEnabled(b);
            }
        }
    }

    public void init() throws Exception {
    }

    private void ensureSecurityManager() {
        WebSecurityManager securityManager = getSecurityManager();
        if (securityManager == null) {
            log.info("No SecurityManager configured.Creating default.");
            securityManager = createDefaultSecurityManager();
            setSecurityManager(securityManager);
        }
    }

    protected WebSecurityManager createDefaultSecurityManager() {
        return new DefaultWebSecurityManager();
    }

    protected boolean isHttpSessions() {
        return getSecurityManager().isHttpSessionMode();
    }

    protected ServletRequest wrapServletRequest(HttpServletRequest orig) {
        return new SecurityHttpServletRequest(orig, getServletContext(), isHttpSessions());
    }

    @SuppressWarnings({"UnusedDeclaration"})
    protected ServletRequest prepareServletRequest(ServletRequest request, ServletResponse response, FilterChain chain) {
        ServletRequest toUse = request;
        if (request instanceof HttpServletRequest) {
            HttpServletRequest http = (HttpServletRequest) request;
            toUse = wrapServletRequest(http);
        }
        return toUse;
    }

    protected ServletResponse wrapServletResponse(HttpServletResponse orig, SecurityHttpServletRequest request) {
        return new SecurityHttpServletResponse(orig, getServletContext(), request);
    }

    @SuppressWarnings({"UnusedDeclaration"})
    protected ServletResponse prepareServletResponse(ServletRequest request, ServletResponse response, FilterChain chain) {
        ServletResponse toUse = response;
        if (!isHttpSessions() && (request instanceof SecurityHttpServletRequest) &&
                (response instanceof HttpServletResponse)) {
            toUse = wrapServletResponse((HttpServletResponse) response, (SecurityHttpServletRequest) request);
        }
        return toUse;
    }

    protected WebSubject createSubject(ServletRequest request, ServletResponse response) {
        return new WebSubject.Builder(getSecurityManager(), request, response).buildWebSubject();
    }


    @SuppressWarnings({"UnusedDeclaration"})
    protected void updateSessionLastAccessTime(ServletRequest request, ServletResponse response) {
        if (!isHttpSessions()) { //'native' sessions
            Subject subject = SecurityUtils.getSubject();
            //Subject should never _ever_ be null, but just in case:
            if (subject != null) {
                Session session = subject.getSession(false);
                if (session != null) {
                    try {
                        session.touch();
                    } catch (Throwable t) {
                        log.error("session.touch() method invocation has failed.  Unable to update" +
                                "the corresponding session's last access time based on the incoming request.", t);
                    }
                }
            }
        }
    }

    /**
     * @param servletRequest  the incoming {@code ServletRequest}
     * @param servletResponse the outgoing {@code ServletResponse}
     * @param chain           the container-provided {@code FilterChain} to execute
     * @throws java.io.IOException            if an IO error occurs
     * @throws javax.servlet.ServletException if an Throwable other than an IOException
     */
    protected void doFilterInternal(ServletRequest servletRequest, ServletResponse servletResponse, final FilterChain chain)
            throws ServletException, IOException {

        Throwable t = null;

        try {
            final ServletRequest request = prepareServletRequest(servletRequest, servletResponse, chain);
            final ServletResponse response = prepareServletResponse(request, servletResponse, chain);

            final Subject subject = createSubject(request, response);

            subject.execute(new Callable() {
                public Object call() throws Exception {
                    updateSessionLastAccessTime(request, response);
                    executeChain(request, response, chain);
                    return null;
                }
            });
        } catch (ExecutionException ex) {
            t = ex.getCause();
        } catch (Throwable throwable) {
            t = throwable;
        }

        if (t != null) {
            if (t instanceof ServletException) {
                throw (ServletException) t;
            }
            if (t instanceof IOException) {
                throw (IOException) t;
            }
            String msg = "Filtered request failed.";
            throw new ServletException(msg, t);
        }
    }

    /**
     * @param request   the incoming ServletRequest
     * @param response  the outgoing ServletResponse
     * @param origChain the original {@code FilterChain} provided by the Servlet Container
     * @return the {@link javax.servlet.FilterChain} to execute for the given request
     * @since 1.0
     */
    protected FilterChain getExecutionChain(ServletRequest request, ServletResponse response, FilterChain origChain) {
        FilterChain chain = origChain;

        FilterChainResolver resolver = getFilterChainResolver();
        if (resolver == null) {
            if (log.isDebugEnabled()) {
                log.debug("No FilterChainResolver configured.  Returning original FilterChain.");
            }
            return origChain;
        }

        FilterChain resolved = resolver.getChain(request, response, origChain);
        if (resolved != null) {
            if (log.isTraceEnabled()) {
                log.trace("Resolved a configured FilterChain for the current request.");
            }
            chain = resolved;
        } else {
            if (log.isTraceEnabled()) {
                log.trace("No FilterChain configured for the current request.  Using the default.");
            }
        }

        return chain;
    }

    /**
     * @param request   the incoming ServletRequest
     * @param response  the outgoing ServletResponse
     * @param origChain the Servlet Container-provided chain that may be wrapped further by an application-configured
     *                  chain of Filters.
     * @throws java.io.IOException            if the underlying {@code chain.doFilter} call results in an IOException
     * @throws javax.servlet.ServletException if the underlying {@code chain.doFilter} call results in a ServletException
     * @since 1.0
     */
    protected void executeChain(ServletRequest request, ServletResponse response, FilterChain origChain)
            throws IOException, ServletException {
        FilterChain chain = getExecutionChain(request, response, origChain);
        chain.doFilter(request, response);
    }
}
