package com.hwlcn.security.web.env;

import com.hwlcn.security.env.Environment;
import com.hwlcn.security.web.filter.mgt.FilterChainResolver;
import com.hwlcn.security.web.mgt.WebSecurityManager;

import javax.servlet.ServletContext;

public interface WebEnvironment extends Environment {

    /**
     * 获取过滤链拦截类
     *
     * @return
     */
    FilterChainResolver getFilterChainResolver();

    /**
     * 获取ServletContext
     *
     * @return
     */
    ServletContext getServletContext();

    /**
     * 获取WebSecurityManager 类
     *
     * @return
     */
    WebSecurityManager getWebSecurityManager();
}
