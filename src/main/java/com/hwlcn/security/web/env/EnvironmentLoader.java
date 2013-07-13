package com.hwlcn.security.web.env;

import com.hwlcn.security.config.ConfigurationException;
import com.hwlcn.security.config.ResourceConfigurable;
import com.hwlcn.security.util.ClassUtils;
import com.hwlcn.security.util.LifecycleUtils;
import com.hwlcn.security.util.StringUtils;
import com.hwlcn.security.util.UnknownClassException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContext;

public class EnvironmentLoader {

    public static final String ENVIRONMENT_CLASS_PARAM = "securityEnvironmentClass";

    public static final String CONFIG_LOCATIONS_PARAM = "securityConfigLocations";

    public static final String ENVIRONMENT_ATTRIBUTE_KEY = EnvironmentLoader.class.getName() + ".ENVIRONMENT_ATTRIBUTE_KEY";

    private static final Logger log = LoggerFactory.getLogger(EnvironmentLoader.class);

    public WebEnvironment initEnvironment(ServletContext servletContext) throws IllegalStateException {

        if (servletContext.getAttribute(ENVIRONMENT_ATTRIBUTE_KEY) != null) {
            String msg = "There is already a Security environment associated with the current ServletContext.  " +
                    "Check if you have multiple EnvironmentLoader* definitions in your web.xml!";
            throw new IllegalStateException(msg);
        }

        servletContext.log("Initializing Security environment");
        if (log.isInfoEnabled()) {
            log.info("Starting Security environment initialization.");
        }
        long startTime = System.currentTimeMillis();

        try {
            WebEnvironment environment = createEnvironment(servletContext);
            servletContext.setAttribute(ENVIRONMENT_ATTRIBUTE_KEY, environment);


            if (log.isInfoEnabled()) {
                long elapsed = System.currentTimeMillis() - startTime;
                log.info("Security environment initialized in {} ms.", elapsed);
            }

            return environment;
        } catch (RuntimeException ex) {
            log.error("Security environment initialization failed", ex);
            servletContext.setAttribute(ENVIRONMENT_ATTRIBUTE_KEY, ex);
            throw ex;
        } catch (Error err) {
            log.error("Security environment initialization failed", err);
            servletContext.setAttribute(ENVIRONMENT_ATTRIBUTE_KEY, err);
            throw err;
        }
    }

    //获取 WebEnvironment的类 类型
    protected Class<?> determineWebEnvironmentClass(ServletContext servletContext) {
        String className = servletContext.getInitParameter(ENVIRONMENT_CLASS_PARAM);
        if (className != null) {
            try {
                return ClassUtils.forName(className);
            } catch (UnknownClassException ex) {
                throw new ConfigurationException(
                        "Failed to load custom WebEnvironment class [" + className + "]", ex);
            }
        } else {
            return IniWebEnvironment.class;
        }
    }

    //环境中的 实体对象要继承 destroyable
    protected WebEnvironment createEnvironment(ServletContext sc) {

        Class<?> clazz = determineWebEnvironmentClass(sc);
        if (!MutableWebEnvironment.class.isAssignableFrom(clazz)) {
            throw new ConfigurationException("Custom WebEnvironment class [" + clazz.getName() +
                    "] is not of required type [" + WebEnvironment.class.getName() + "]");
        }

        String configLocations = sc.getInitParameter(CONFIG_LOCATIONS_PARAM);
        boolean configSpecified = StringUtils.hasText(configLocations);

        if (configSpecified && !(ResourceConfigurable.class.isAssignableFrom(clazz))) {
            String msg = "WebEnvironment class [" + clazz.getName() + "] does not implement the " +
                    ResourceConfigurable.class.getName() + "interface.  This is required to accept any " +
                    "configured " + CONFIG_LOCATIONS_PARAM + "value(s).";
            throw new ConfigurationException(msg);
        }

        MutableWebEnvironment environment = (MutableWebEnvironment) ClassUtils.newInstance(clazz);

        environment.setServletContext(sc);

        if (configSpecified && (environment instanceof ResourceConfigurable)) {
            ((ResourceConfigurable) environment).setConfigLocations(configLocations);
        }

        customizeEnvironment(environment);

        LifecycleUtils.init(environment);

        return environment;
    }

    protected void customizeEnvironment(WebEnvironment environment) {
    }


    public void destroyEnvironment(ServletContext servletContext) {
        servletContext.log("Cleaning up Security Environment");
        try {
            Object environment = servletContext.getAttribute(ENVIRONMENT_ATTRIBUTE_KEY);
            LifecycleUtils.destroy(environment);
        } finally {
            servletContext.removeAttribute(ENVIRONMENT_ATTRIBUTE_KEY);
        }
    }
}
