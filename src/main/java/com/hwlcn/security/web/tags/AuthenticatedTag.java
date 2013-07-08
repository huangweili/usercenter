package com.hwlcn.security.web.tags;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.TagSupport;


public class AuthenticatedTag extends SecureTag {

    private static final Logger log = LoggerFactory.getLogger(AuthenticatedTag.class);

    public int onDoStartTag() throws JspException {
        if (getSubject() != null && getSubject().isAuthenticated()) {
            if (log.isTraceEnabled()) {
                log.trace("Subject exists and is authenticated.  Tag body will be evaluated.");
            }
            return TagSupport.EVAL_BODY_INCLUDE;
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Subject does not exist or is not authenticated.  Tag body will not be evaluated.");
            }
            return TagSupport.SKIP_BODY;
        }
    }
}