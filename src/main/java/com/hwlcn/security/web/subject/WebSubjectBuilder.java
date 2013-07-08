package com.hwlcn.security.web.subject;

import com.hwlcn.security.SecurityUtils;
import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.subject.SubjectBuilder;
import com.hwlcn.security.subject.SubjectContext;
import com.hwlcn.security.web.subject.support.DefaultWebSubjectContext;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * User: HuangWeili
 * Date: 13-7-8
 * Time: 下午10:23
 */
public class WebSubjectBuilder extends SubjectBuilder {

    public WebSubjectBuilder(ServletRequest request, ServletResponse response) {
        this(SecurityUtils.getSecurityManager(), request, response);
    }

    public WebSubjectBuilder(com.hwlcn.security.mgt.SecurityManager securityManager, ServletRequest request, ServletResponse response) {
        super(securityManager);
        if (request == null) {
            throw new IllegalArgumentException("ServletRequest argument cannot be null.");
        }
        if (response == null) {
            throw new IllegalArgumentException("ServletResponse argument cannot be null.");
        }
        setRequest(request);
        setResponse(response);
    }

    @Override
    protected SubjectContext newSubjectContextInstance() {
        return new DefaultWebSubjectContext();
    }


    protected WebSubjectBuilder setRequest(ServletRequest request) {
        if (request != null) {
            ((WebSubjectContext) getSubjectContext()).setServletRequest(request);
        }
        return this;
    }

    protected WebSubjectBuilder setResponse(ServletResponse response) {
        if (response != null) {
            ((WebSubjectContext) getSubjectContext()).setServletResponse(response);
        }
        return this;
    }

    public WebSubject buildWebSubject() {
        Subject subject = super.buildSubject();
        if (!(subject instanceof WebSubject)) {
            String msg = "Subject implementation returned from the SecurityManager was not a " +
                    WebSubject.class.getName() + " implementation.  Please ensure a Web-enabled SecurityManager " +
                    "has been configured and made available to this builder.";
            throw new IllegalStateException(msg);
        }
        return (WebSubject) subject;
    }
}
