
package com.hwlcn.security.web.env;

import com.hwlcn.security.web.filter.mgt.FilterChainResolver;
import com.hwlcn.security.web.mgt.WebSecurityManager;

import javax.servlet.ServletContext;


public interface MutableWebEnvironment extends WebEnvironment {


    void setFilterChainResolver(FilterChainResolver filterChainResolver);

    void setServletContext(ServletContext servletContext);


    void setWebSecurityManager(WebSecurityManager webSecurityManager);
}
