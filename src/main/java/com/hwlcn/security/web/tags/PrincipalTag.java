package com.hwlcn.security.web.tags;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.JspTagException;
import java.beans.BeanInfo;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.io.IOException;


//人员信息标签
public class PrincipalTag extends SecureTag {


    private static final Logger log = LoggerFactory.getLogger(PrincipalTag.class);

    private String type;

    private String property;

    private String defaultValue;


    public String getType() {
        return type;
    }


    public void setType(String type) {
        this.type = type;
    }


    public String getProperty() {
        return property;
    }


    public void setProperty(String property) {
        this.property = property;
    }


    public String getDefaultValue() {
        return defaultValue;
    }


    public void setDefaultValue(String defaultValue) {
        this.defaultValue = defaultValue;
    }


    @SuppressWarnings({"unchecked"})
    public int onDoStartTag() throws JspException {
        String strValue = null;

        if (getSubject() != null) {
            Object principal;

            if (type == null) {
                principal = getSubject().getPrincipal();
            } else {
                principal = getPrincipalFromClassName();
            }

            if (principal != null) {
                if (property == null) {
                    strValue = principal.toString();
                } else {
                    strValue = getPrincipalProperty(principal, property);
                }
            }

        }

        if (strValue != null) {
            try {
                pageContext.getOut().write(strValue);
            } catch (IOException e) {
                throw new JspTagException("Error writing [" + strValue + "] to JSP.", e);
            }
        }

        return SKIP_BODY;
    }

    @SuppressWarnings({"unchecked"})
    private Object getPrincipalFromClassName() {
        Object principal = null;

        try {
            Class cls = Class.forName(type);
            principal = getSubject().getPrincipals().oneByType(cls);
        } catch (ClassNotFoundException e) {
            if (log.isErrorEnabled()) {
                log.error("Unable to find class for name [" + type + "]");
            }
        }
        return principal;
    }


    private String getPrincipalProperty(Object principal, String property) throws JspTagException {
        String strValue = null;

        try {
            BeanInfo bi = Introspector.getBeanInfo(principal.getClass());

            boolean foundProperty = false;
            for (PropertyDescriptor pd : bi.getPropertyDescriptors()) {
                if (pd.getName().equals(property)) {
                    Object value = pd.getReadMethod().invoke(principal, (Object[]) null);
                    strValue = String.valueOf(value);
                    foundProperty = true;
                    break;
                }
            }

            if (!foundProperty) {
                final String message = "Property [" + property + "] not found in principal of type [" + principal.getClass().getName() + "]";
                if (log.isErrorEnabled()) {
                    log.error(message);
                }
                throw new JspTagException(message);
            }

        } catch (Exception e) {
            final String message = "Error reading property [" + property + "] from principal of type [" + principal.getClass().getName() + "]";
            if (log.isErrorEnabled()) {
                log.error(message, e);
            }
            throw new JspTagException(message, e);
        }

        return strValue;
    }
}