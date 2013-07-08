package com.hwlcn.security.web.subject;

import com.hwlcn.security.subject.SubjectContext;
import com.hwlcn.security.web.util.RequestPairSource;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


public interface WebSubjectContext extends SubjectContext, RequestPairSource {

    ServletRequest getServletRequest();

    void setServletRequest(ServletRequest request);

    ServletRequest resolveServletRequest();

    ServletResponse getServletResponse();

    void setServletResponse(ServletResponse response);

    ServletResponse resolveServletResponse();
}
