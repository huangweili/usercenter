package com.hwlcn.security.web.tags;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.TagSupport;


public class GuestTag extends SecureTag {


    private static final Logger log = LoggerFactory.getLogger(GuestTag.class);

    public int onDoStartTag() throws JspException {
        if (getSubject() == null || getSubject().getPrincipal() == null) {
            if (log.isTraceEnabled()) {
                log.trace("Subject does not exist or does not have a known identity (aka 'principal').  " +
                        "Tag body will be evaluated.");
            }
            return TagSupport.EVAL_BODY_INCLUDE;
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Subject exists or has a known identity (aka 'principal').  " +
                        "Tag body will not be evaluated.");
            }
            return TagSupport.SKIP_BODY;
        }
    }

}
