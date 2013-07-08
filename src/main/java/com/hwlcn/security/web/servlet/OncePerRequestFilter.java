package com.hwlcn.security.web.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

public abstract class OncePerRequestFilter extends NameableFilter {

    private static final Logger log = LoggerFactory.getLogger(OncePerRequestFilter.class);

    public static final String ALREADY_FILTERED_SUFFIX = ".FILTERED";

    private boolean enabled = true;


    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public final void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {


        String alreadyFilteredAttributeName = getAlreadyFilteredAttributeName();

        if (request.getAttribute(alreadyFilteredAttributeName) != null) {
            if (log.isTraceEnabled()) {
                log.trace("Filter '{}' already executed.  Proceeding without invoking this filter.", getName());
            }
            filterChain.doFilter(request, response);

        } else if (!isEnabled(request, response)) {
            if (log.isDebugEnabled()) {
                log.debug("Filter '{}' is not enabled for the current request.  Proceeding without invoking this filter.",
                        getName());
            }
            filterChain.doFilter(request, response);
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Filter '{}' not yet executed.  Executing now.", getName());
            }

            request.setAttribute(alreadyFilteredAttributeName, Boolean.TRUE);

            try {
                doFilterInternal(request, response, filterChain);
            } finally {
                request.removeAttribute(alreadyFilteredAttributeName);
            }
        }
    }

    protected boolean isEnabled(ServletRequest request, ServletResponse response) throws ServletException, IOException {
        return isEnabled();
    }

    protected String getAlreadyFilteredAttributeName() {
        String name = getName();
        if (name == null) {
            name = getClass().getName();
        }
        return name + ALREADY_FILTERED_SUFFIX;
    }


    protected abstract void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
            throws ServletException, IOException;
}
