package com.hwlcn.security.web.filter.authc;

import com.hwlcn.security.SecurityUtils;
import com.hwlcn.security.session.SessionException;
import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.web.servlet.AdviceFilter;
import com.hwlcn.security.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


public class LogoutFilter extends AdviceFilter {

    private static final Logger log = LoggerFactory.getLogger(LogoutFilter.class);

    public static final String DEFAULT_REDIRECT_URL = "/";

    private String redirectUrl = DEFAULT_REDIRECT_URL;

    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        Subject subject = getSubject(request, response);
        String redirectUrl = getRedirectUrl(request, response, subject);
        try {
            subject.logout();
        } catch (SessionException ise) {
            if (log.isDebugEnabled()) {
                log.debug("Encountered session exception during logout.  This can generally safely be ignored.", ise);
            }
        }
        issueRedirect(request, response, redirectUrl);
        return false;
    }


    protected Subject getSubject(ServletRequest request, ServletResponse response) {
        return SecurityUtils.getSubject();
    }

    protected void issueRedirect(ServletRequest request, ServletResponse response, String redirectUrl) throws Exception {
        WebUtils.issueRedirect(request, response, redirectUrl);
    }

    protected String getRedirectUrl(ServletRequest request, ServletResponse response, Subject subject) {
        return getRedirectUrl();
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

    public void setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }
}
