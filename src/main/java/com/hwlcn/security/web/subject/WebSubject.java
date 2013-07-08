package com.hwlcn.security.web.subject;

import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.web.util.RequestPairSource;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * WebSubject 接口
 */
public interface WebSubject extends Subject, RequestPairSource {

    ServletRequest getServletRequest();

    ServletResponse getServletResponse();
}
