
package com.hwlcn.security.jndi;

import java.util.Properties;
import javax.naming.NamingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class JndiLocator {


    private static final Logger log = LoggerFactory.getLogger(JndiLocator.class);


    public static final String CONTAINER_PREFIX = "java:comp/env/";

    private boolean resourceRef = false;

    private JndiTemplate jndiTemplate = new JndiTemplate();



    public void setJndiTemplate(JndiTemplate jndiTemplate) {
        this.jndiTemplate = (jndiTemplate != null ? jndiTemplate : new JndiTemplate());
    }


    public JndiTemplate getJndiTemplate() {
        return this.jndiTemplate;
    }


    public void setJndiEnvironment(Properties jndiEnvironment) {
        this.jndiTemplate = new JndiTemplate(jndiEnvironment);
    }


    public Properties getJndiEnvironment() {
        return this.jndiTemplate.getEnvironment();
    }


    public void setResourceRef(boolean resourceRef) {
        this.resourceRef = resourceRef;
    }

    public boolean isResourceRef() {
        return this.resourceRef;
    }



    protected Object lookup(String jndiName) throws NamingException {
        return lookup(jndiName, null);
    }


    protected Object lookup(String jndiName, Class requiredType) throws NamingException {
        if (jndiName == null) {
            throw new IllegalArgumentException("jndiName argument must not be null");
        }
        String convertedName = convertJndiName(jndiName);
        Object jndiObject;
        try {
            jndiObject = getJndiTemplate().lookup(convertedName, requiredType);
        }
        catch (NamingException ex) {
            if (!convertedName.equals(jndiName)) {

                if (log.isDebugEnabled()) {
                    log.debug("Converted JNDI name [" + convertedName +
                            "] not found - trying original name [" + jndiName + "]. " + ex);
                }
                jndiObject = getJndiTemplate().lookup(jndiName, requiredType);
            } else {
                throw ex;
            }
        }
        log.debug("Located object with JNDI name '{}'", convertedName);
        return jndiObject;
    }


    protected String convertJndiName(String jndiName) {
        if (isResourceRef() && !jndiName.startsWith(CONTAINER_PREFIX) && jndiName.indexOf(':') == -1) {
            jndiName = CONTAINER_PREFIX + jndiName;
        }
        return jndiName;
    }

}
