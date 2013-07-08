package com.hwlcn.security.web.filter.authc;

import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.web.filter.AccessControlFilter;
import com.hwlcn.security.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


public abstract class AuthenticationFilter extends AccessControlFilter {


    public static final String DEFAULT_SUCCESS_URL = "/";

    private String successUrl = DEFAULT_SUCCESS_URL;

    public String getSuccessUrl() {
        return successUrl;
    }

    public void setSuccessUrl(String successUrl) {
        this.successUrl = successUrl;
    }


    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        Subject subject = getSubject(request, response);
        return subject.isAuthenticated();
    }

    /**
     * 成功后的跳转界面
     *
     * @param request
     * @param response
     * @throws Exception
     */
    protected void issueSuccessRedirect(ServletRequest request, ServletResponse response) throws Exception {
        WebUtils.redirectToSavedRequest(request, response, getSuccessUrl());
    }

}
