
package com.hwlcn.security.web.subject.support;

import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.subject.support.DefaultSubjectContext;
import com.hwlcn.security.web.subject.WebSubject;
import com.hwlcn.security.web.subject.WebSubjectContext;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * Default {@code WebSubjectContext} implementation that provides for additional storage and retrieval of
 * a {@link javax.servlet.ServletRequest} and {@link javax.servlet.ServletResponse}.
 *
 * @since 1.0
 */
public class DefaultWebSubjectContext extends DefaultSubjectContext implements WebSubjectContext {

    private static final long serialVersionUID = 8188555355305827739L;

    private static final String SERVLET_REQUEST = DefaultWebSubjectContext.class.getName() + ".SERVLET_REQUEST";
    private static final String SERVLET_RESPONSE = DefaultWebSubjectContext.class.getName() + ".SERVLET_RESPONSE";

    public DefaultWebSubjectContext() {
    }

    public DefaultWebSubjectContext(WebSubjectContext context) {
        super(context);
    }

    @Override
    public String resolveHost() {
        String host = super.resolveHost();
        if (host == null) {
            ServletRequest request = resolveServletRequest();
            if (request != null) {
                host = request.getRemoteHost();
            }
        }
        return host;
    }

    public ServletRequest getServletRequest() {
        return getTypedValue(SERVLET_REQUEST, ServletRequest.class);
    }

    public void setServletRequest(ServletRequest request) {
        if (request != null) {
            put(SERVLET_REQUEST, request);
        }
    }

    public ServletRequest resolveServletRequest() {

        ServletRequest request = getServletRequest();

        //fall back on existing subject instance if it exists:
        if (request == null) {
            Subject existing = getSubject();
            if (existing instanceof WebSubject) {
                request = ((WebSubject) existing).getServletRequest();
            }
        }

        return request;
    }

    public ServletResponse getServletResponse() {
        return getTypedValue(SERVLET_RESPONSE, ServletResponse.class);
    }

    public void setServletResponse(ServletResponse response) {
        if (response != null) {
            put(SERVLET_RESPONSE, response);
        }
    }

    public ServletResponse resolveServletResponse() {

        ServletResponse response = getServletResponse();

        //fall back on existing subject instance if it exists:
        if (response == null) {
            Subject existing = getSubject();
            if (existing instanceof WebSubject) {
                response = ((WebSubject) existing).getServletResponse();
            }
        }

        return response;
    }
}
