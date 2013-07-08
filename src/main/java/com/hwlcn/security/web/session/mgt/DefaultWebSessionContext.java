package com.hwlcn.security.web.session.mgt;

import com.hwlcn.security.session.mgt.DefaultSessionContext;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.Map;

public class DefaultWebSessionContext extends DefaultSessionContext implements WebSessionContext {

    private static final long serialVersionUID = -3974604687792523072L;

    private static final String SERVLET_REQUEST = DefaultWebSessionContext.class.getName() + ".SERVLET_REQUEST";
    private static final String SERVLET_RESPONSE = DefaultWebSessionContext.class.getName() + ".SERVLET_RESPONSE";

    public DefaultWebSessionContext() {
        super();
    }

    public DefaultWebSessionContext(Map<String, Object> map) {
        super(map);
    }

    public void setServletRequest(ServletRequest request) {
        if (request != null) {
            put(SERVLET_REQUEST, request);
        }
    }

    public ServletRequest getServletRequest() {
        return getTypedValue(SERVLET_REQUEST, ServletRequest.class);
    }

    public void setServletResponse(ServletResponse response) {
        if (response != null) {
            put(SERVLET_RESPONSE, response);
        }
    }

    public ServletResponse getServletResponse() {
        return getTypedValue(SERVLET_RESPONSE, ServletResponse.class);
    }
}
