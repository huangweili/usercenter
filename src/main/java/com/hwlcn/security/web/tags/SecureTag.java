package com.hwlcn.security.web.tags;

import com.hwlcn.security.SecurityUtils;
import com.hwlcn.security.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.TagSupport;

public abstract class SecureTag extends TagSupport {

    private static final Logger log = LoggerFactory.getLogger(SecureTag.class);

    public SecureTag() {
    }

    @Override
    public int doEndTag() throws JspException {
        return super.doEndTag();
    }

    //获取线程内的对象
    protected Subject getSubject() {
        return SecurityUtils.getSubject();
    }

    protected void verifyAttributes() throws JspException {
    }

    public int doStartTag() throws JspException {

        verifyAttributes();

        return onDoStartTag();
    }

    public abstract int onDoStartTag() throws JspException;
}
