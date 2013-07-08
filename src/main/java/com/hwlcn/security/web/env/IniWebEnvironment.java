package com.hwlcn.security.web.env;

import com.hwlcn.security.config.ConfigurationException;
import com.hwlcn.security.config.Ini;
import com.hwlcn.security.config.IniFactorySupport;
import com.hwlcn.security.io.ResourceUtils;
import com.hwlcn.security.util.CollectionUtils;
import com.hwlcn.security.util.Destroyable;
import com.hwlcn.security.util.Initializable;
import com.hwlcn.security.util.StringUtils;
import com.hwlcn.security.web.config.IniFilterChainResolverFactory;
import com.hwlcn.security.web.config.WebIniSecurityManagerFactory;
import com.hwlcn.security.web.filter.mgt.FilterChainResolver;
import com.hwlcn.security.web.mgt.WebSecurityManager;
import com.hwlcn.security.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContext;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;


public class IniWebEnvironment extends ResourceBasedWebEnvironment implements Initializable, Destroyable {

    public static final String DEFAULT_WEB_INI_RESOURCE_PATH = "/WEB-INF/security.ini";

    private static final Logger log = LoggerFactory.getLogger(IniWebEnvironment.class);

    private Ini ini;

    public void init() {
        Ini ini = getIni();

        String[] configLocations = getConfigLocations();

        if (log.isWarnEnabled() && !CollectionUtils.isEmpty(ini) &&
                configLocations != null && configLocations.length > 0) {
            log.warn("Explicit INI instance has been provided, but configuration locations have also been " +
                    "specified.  The {} implementation does not currently support multiple Ini config, but this may " +
                    "be supported in the future. Only the INI instance will be used for configuration.",
                    IniWebEnvironment.class.getName());
        }

        if (CollectionUtils.isEmpty(ini)) {
            log.debug("Checking any specified config locations.");
            ini = getSpecifiedIni(configLocations);
        }

        if (CollectionUtils.isEmpty(ini)) {
            log.debug("No INI instance or config locations specified.  Trying default config locations.");
            ini = getDefaultIni();
        }

        if (CollectionUtils.isEmpty(ini)) {
            String msg = "Security INI configuration was either not found or discovered to be empty/unconfigured.";
            throw new ConfigurationException(msg);
        }

        setIni(ini);

        configure();
    }

    protected void configure() {

        this.objects.clear();

        WebSecurityManager securityManager = createWebSecurityManager();
        setWebSecurityManager(securityManager);

        FilterChainResolver resolver = createFilterChainResolver();
        if (resolver != null) {
            setFilterChainResolver(resolver);
        }
    }

    protected Ini getSpecifiedIni(String[] configLocations) throws ConfigurationException {

        Ini ini = null;

        if (configLocations != null && configLocations.length > 0) {

            if (configLocations.length > 1) {
                log.warn("More than one Security .ini config location has been specified.  Only the first will be " +
                        "used for configuration as the {} implementation does not currently support multiple " +
                        "files.  This may be supported in the future however.", IniWebEnvironment.class.getName());
            }

            ini = createIni(configLocations[0], true);
        }

        return ini;
    }

    protected Ini getDefaultIni() {

        Ini ini = null;

        String[] configLocations = getDefaultConfigLocations();
        if (configLocations != null) {
            for (String location : configLocations) {
                ini = createIni(location, false);
                if (!CollectionUtils.isEmpty(ini)) {
                    log.debug("Discovered non-empty INI configuration at location '{}'.  Using for configuration.",
                            location);
                    break;
                }
            }
        }

        return ini;
    }


    protected Ini createIni(String configLocation, boolean required) throws ConfigurationException {

        Ini ini = null;

        if (configLocation != null) {
            ini = convertPathToIni(configLocation, required);
        }
        if (required && CollectionUtils.isEmpty(ini)) {
            String msg = "Required configuration location '" + configLocation + "' does not exist or did not " +
                    "contain any INI configuration.";
            throw new ConfigurationException(msg);
        }

        return ini;
    }

    protected FilterChainResolver createFilterChainResolver() {

        FilterChainResolver resolver = null;

        Ini ini = getIni();

        if (!CollectionUtils.isEmpty(ini)) {
            Ini.Section urls = ini.getSection(IniFilterChainResolverFactory.URLS);
            Ini.Section filters = ini.getSection(IniFilterChainResolverFactory.FILTERS);
            if (!CollectionUtils.isEmpty(urls) || !CollectionUtils.isEmpty(filters)) {
                IniFilterChainResolverFactory factory = new IniFilterChainResolverFactory(ini, this.objects);
                resolver = factory.getInstance();
            }
        }

        return resolver;
    }

    protected WebSecurityManager createWebSecurityManager() {
        WebIniSecurityManagerFactory factory;
        Ini ini = getIni();
        if (CollectionUtils.isEmpty(ini)) {
            factory = new WebIniSecurityManagerFactory();
        } else {
            factory = new WebIniSecurityManagerFactory(ini);
        }

        WebSecurityManager wsm = (WebSecurityManager) factory.getInstance();

        Map<String, ?> beans = factory.getBeans();
        if (!CollectionUtils.isEmpty(beans)) {
            this.objects.putAll(beans);
        }

        return wsm;
    }

    protected String[] getDefaultConfigLocations() {
        return new String[]{
                DEFAULT_WEB_INI_RESOURCE_PATH,
                IniFactorySupport.DEFAULT_INI_RESOURCE_PATH
        };
    }

    private Ini convertPathToIni(String path, boolean required) {


        Ini ini = null;

        if (StringUtils.hasText(path)) {
            InputStream is = null;
            if (!ResourceUtils.hasResourcePrefix(path)) {
                is = getServletContextResourceStream(path);
            } else {
                try {
                    is = ResourceUtils.getInputStreamForPath(path);
                } catch (IOException e) {
                    if (required) {
                        throw new ConfigurationException(e);
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("Unable to load optional path '" + path + "'.", e);
                        }
                    }
                }
            }
            if (is != null) {
                ini = new Ini();
                ini.load(is);
            } else {
                if (required) {
                    throw new ConfigurationException("Unable to load resource path '" + path + "'");
                }
            }
        }

        return ini;
    }

    private InputStream getServletContextResourceStream(String path) {
        InputStream is = null;

        path = WebUtils.normalize(path);
        ServletContext sc = getServletContext();
        if (sc != null) {
            is = sc.getResourceAsStream(path);
        }

        return is;
    }

    public Ini getIni() {
        return this.ini;
    }

    public void setIni(Ini ini) {
        this.ini = ini;
    }
}
