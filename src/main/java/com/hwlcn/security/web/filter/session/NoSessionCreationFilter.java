package com.hwlcn.security.web.filter.session;

import com.hwlcn.security.subject.support.DefaultSubjectContext;
import com.hwlcn.security.web.filter.PathMatchingFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class NoSessionCreationFilter extends PathMatchingFilter {

    @Override
    protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        request.setAttribute(DefaultSubjectContext.SESSION_CREATION_ENABLED, Boolean.FALSE);
        return true;
    }
}
