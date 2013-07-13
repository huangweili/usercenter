package com.hwlcn.security.web.filter.authc;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
public class PassThruAuthenticationFilter extends AuthenticationFilter {


    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        if (isLoginRequest(request, response)) {
            return true;
        } else {
            saveRequestAndRedirectToLogin(request, response);
            return false;
        }
    }

}
