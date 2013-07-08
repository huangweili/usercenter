package com.hwlcn.security.web.session.mgt;

import com.hwlcn.security.session.mgt.SessionContext;
import com.hwlcn.security.web.util.RequestPairSource;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public interface WebSessionContext extends SessionContext, RequestPairSource {

    ServletRequest getServletRequest();

    void setServletRequest(ServletRequest request);

    ServletResponse getServletResponse();

    void setServletResponse(ServletResponse response);
}
