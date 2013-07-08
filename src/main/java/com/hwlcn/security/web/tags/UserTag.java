package com.hwlcn.security.web.tags;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.jsp.JspException;


public class UserTag extends SecureTag {


    private static final Logger log = LoggerFactory.getLogger(UserTag.class);

    public int onDoStartTag() throws JspException {
        if (getSubject() != null && getSubject().getPrincipal() != null) {
            if (log.isTraceEnabled()) {
                log.trace("Subject has known identity (aka 'principal').  " +
                        "Tag body will be evaluated.");
            }
            return EVAL_BODY_INCLUDE;
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Subject does not exist or have a known identity (aka 'principal').  " +
                        "Tag body will not be evaluated.");
            }
            return SKIP_BODY;
        }
    }

}
