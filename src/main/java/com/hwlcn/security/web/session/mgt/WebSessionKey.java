package com.hwlcn.security.web.session.mgt;

import com.hwlcn.security.session.mgt.DefaultSessionKey;
import com.hwlcn.security.web.util.RequestPairSource;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.Serializable;

public class WebSessionKey extends DefaultSessionKey implements RequestPairSource {

    private final ServletRequest servletRequest;
    private final ServletResponse servletResponse;

    public WebSessionKey(ServletRequest request, ServletResponse response) {
        if (request == null) {
            throw new NullPointerException("request argument cannot be null.");
        }
        if (response == null) {
            throw new NullPointerException("response argument cannot be null.");
        }
        this.servletRequest = request;
        this.servletResponse = response;
    }

    public WebSessionKey(Serializable sessionId, ServletRequest request, ServletResponse response) {
        this(request, response);
        setSessionId(sessionId);
    }

    public ServletRequest getServletRequest() {
        return servletRequest;
    }

    public ServletResponse getServletResponse() {
        return servletResponse;
    }
}
