package com.hwlcn.security.web.servlet;

import com.hwlcn.security.web.env.WebEnvironment;
import com.hwlcn.security.web.filter.mgt.FilterChainResolver;
import com.hwlcn.security.web.util.WebUtils;


public class SecurityFilter extends AbstractSecurityFilter {

    @Override
    public void init() throws Exception {
        WebEnvironment env = WebUtils.getRequiredWebEnvironment(getServletContext());

        setSecurityManager(env.getWebSecurityManager());

        FilterChainResolver resolver = env.getFilterChainResolver();
        if (resolver != null) {
            setFilterChainResolver(resolver);
        }
    }
}
