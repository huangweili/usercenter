package com.hwlcn.security.web.env;

import com.hwlcn.security.env.Environment;
import com.hwlcn.security.web.filter.mgt.FilterChainResolver;
import com.hwlcn.security.web.mgt.WebSecurityManager;

import javax.servlet.ServletContext;

public interface WebEnvironment extends Environment {

    FilterChainResolver getFilterChainResolver();

    ServletContext getServletContext();

    WebSecurityManager getWebSecurityManager();
}
