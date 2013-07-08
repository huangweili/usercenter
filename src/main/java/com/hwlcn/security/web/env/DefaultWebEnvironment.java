package com.hwlcn.security.web.env;

import com.hwlcn.security.env.DefaultEnvironment;
import com.hwlcn.security.mgt.SecurityManager;
import com.hwlcn.security.web.filter.mgt.FilterChainResolver;
import com.hwlcn.security.web.mgt.WebSecurityManager;

import javax.servlet.ServletContext;

public class DefaultWebEnvironment extends DefaultEnvironment implements MutableWebEnvironment {

    private static final String DEFAULT_FILTER_CHAIN_RESOLVER_NAME = "filterChainResolver";

    private ServletContext servletContext;

    public DefaultWebEnvironment() {
        super();
    }

    public FilterChainResolver getFilterChainResolver() {
        return getObject(DEFAULT_FILTER_CHAIN_RESOLVER_NAME, FilterChainResolver.class);
    }

    public void setFilterChainResolver(FilterChainResolver filterChainResolver) {
        setObject(DEFAULT_FILTER_CHAIN_RESOLVER_NAME, filterChainResolver);
    }

    @Override
    public SecurityManager getSecurityManager() throws IllegalStateException {
        return getWebSecurityManager();
    }

    @Override
    public void setSecurityManager(SecurityManager securityManager) {
        assertWebSecurityManager(securityManager);
        super.setSecurityManager(securityManager);
    }

    public WebSecurityManager getWebSecurityManager() {
        SecurityManager sm = super.getSecurityManager();
        assertWebSecurityManager(sm);
        return (WebSecurityManager) sm;
    }

    public void setWebSecurityManager(WebSecurityManager wsm) {
        super.setSecurityManager(wsm);
    }

    private void assertWebSecurityManager(SecurityManager sm) {
        if (!(sm instanceof WebSecurityManager)) {
            String msg = "SecurityManager instance must be a " + WebSecurityManager.class.getName() + " instance.";
            throw new IllegalStateException(msg);
        }
    }

    public ServletContext getServletContext() {
        return this.servletContext;
    }

    public void setServletContext(ServletContext servletContext) {
        this.servletContext = servletContext;
    }
}
