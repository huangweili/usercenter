package com.hwlcn.security.web.servlet;

import com.hwlcn.security.config.ConfigurationException;
import com.hwlcn.security.config.Ini;
import com.hwlcn.security.config.IniFactorySupport;
import com.hwlcn.security.io.ResourceUtils;
import com.hwlcn.security.mgt.SecurityManager;
import com.hwlcn.security.util.CollectionUtils;
import com.hwlcn.security.util.StringUtils;
import com.hwlcn.security.web.config.IniFilterChainResolverFactory;
import com.hwlcn.security.web.config.WebIniSecurityManagerFactory;
import com.hwlcn.security.web.filter.mgt.FilterChainResolver;
import com.hwlcn.security.web.mgt.WebSecurityManager;
import com.hwlcn.security.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.util.Map;

@Deprecated
public class IniSecurityFilter extends AbstractSecurityFilter {

    public static final String CONFIG_INIT_PARAM_NAME = "config";
    public static final String CONFIG_PATH_INIT_PARAM_NAME = "configPath";

    public static final String DEFAULT_WEB_INI_RESOURCE_PATH = "/WEB-INF/security.ini";

    private static final Logger log = LoggerFactory.getLogger(IniSecurityFilter.class);

    private String config;
    private String configPath;

    public IniSecurityFilter() {
    }


    public String getConfig() {
        return this.config;
    }


    public void setConfig(String config) {
        this.config = config;
    }


    public String getConfigPath() {
        return configPath;
    }


    public void setConfigPath(String configPath) {
        this.configPath = StringUtils.clean(configPath);
    }

    public void init() throws Exception {
        applyInitParams();
        configure();
    }

    protected void applyInitParams() throws Exception {
        String config = getInitParam(CONFIG_INIT_PARAM_NAME);
        if (config != null) {
            setConfig(config);
        }
        String configPath = getInitParam(CONFIG_PATH_INIT_PARAM_NAME);
        if (configPath != null) {
            setConfigPath(configPath);
        }
    }

    protected void configure() throws Exception {
        Ini ini = loadIniFromConfig();

        if (CollectionUtils.isEmpty(ini)) {
            log.info("Null or empty configuration specified via 'config' init-param.  " +
                    "Checking path-based configuration.");
            ini = loadIniFromPath();
        }
        if (CollectionUtils.isEmpty(ini)) {
            log.info("Null or empty configuration specified via '" + CONFIG_INIT_PARAM_NAME + "' or '" +
                    CONFIG_PATH_INIT_PARAM_NAME + "' filter parameters.  Trying the default " +
                    DEFAULT_WEB_INI_RESOURCE_PATH + " file.");
            ini = getServletContextIniResource(DEFAULT_WEB_INI_RESOURCE_PATH);
        }

        if (CollectionUtils.isEmpty(ini)) {
            log.info("Null or empty configuration specified via '" + CONFIG_INIT_PARAM_NAME + "' or '" +
                    CONFIG_PATH_INIT_PARAM_NAME + "' filter parameters.  Trying the default " +
                    IniFactorySupport.DEFAULT_INI_RESOURCE_PATH + " file.");
            ini = IniFactorySupport.loadDefaultClassPathIni();
        }

        Map<String, ?> objects = applySecurityManager(ini);
        applyFilterChainResolver(ini, objects);
    }

    protected Ini loadIniFromConfig() {
        Ini ini = null;
        String config = getConfig();
        if (config != null) {
            ini = convertConfigToIni(config);
        }
        return ini;
    }

    protected Ini loadIniFromPath() {
        Ini ini = null;
        String path = getConfigPath();
        if (path != null) {
            ini = convertPathToIni(path);
        }
        return ini;
    }

    protected Map<String, ?> applySecurityManager(Ini ini) {
        WebIniSecurityManagerFactory factory;
        if (CollectionUtils.isEmpty(ini)) {
            factory = new WebIniSecurityManagerFactory();
        } else {
            factory = new WebIniSecurityManagerFactory(ini);
        }

        SecurityManager securityManager = factory.getInstance();
        if (!(securityManager instanceof WebSecurityManager)) {
            String msg = "The configured security manager is not an instance of WebSecurityManager, so " +
                    "it can not be used with the Shiro servlet filter.";
            throw new ConfigurationException(msg);
        }

        setSecurityManager((WebSecurityManager) securityManager);

        return factory.getBeans();
    }

    protected void applyFilterChainResolver(Ini ini, Map<String, ?> defaults) {
        if (ini == null || ini.isEmpty()) {
            return;
        }
        Ini.Section urls = ini.getSection(IniFilterChainResolverFactory.URLS);
        Ini.Section filters = ini.getSection(IniFilterChainResolverFactory.FILTERS);
        if ((urls != null && !urls.isEmpty()) || (filters != null && !filters.isEmpty())) {
            IniFilterChainResolverFactory filterChainResolverFactory = new IniFilterChainResolverFactory(ini, defaults);
            filterChainResolverFactory.setFilterConfig(getFilterConfig());
            FilterChainResolver resolver = filterChainResolverFactory.getInstance();
            setFilterChainResolver(resolver);
        }
    }

    protected Ini convertConfigToIni(String config) {
        Ini ini = new Ini();
        ini.load(config);
        return ini;
    }

    protected Ini getServletContextIniResource(String servletContextPath) {
        String path = WebUtils.normalize(servletContextPath);
        if (getServletContext() != null) {
            InputStream is = getServletContext().getResourceAsStream(path);
            if (is != null) {
                Ini ini = new Ini();
                ini.load(is);
                if (CollectionUtils.isEmpty(ini)) {
                    log.warn("ServletContext INI resource '" + servletContextPath + "' exists, but it did not contain " +
                            "any data.");
                }
                return ini;
            }
        }
        return null;
    }


    protected Ini convertPathToIni(String path) {

        Ini ini = new Ini();

        if (!ResourceUtils.hasResourcePrefix(path)) {
            ini = getServletContextIniResource(path);
            if (ini == null) {
                String msg = "There is no servlet context resource corresponding to configPath '" + path + "'  If " +
                        "the resource is located elsewhere (not immediately resolveable in the servlet context), " +
                        "specify an appropriate classpath:, url:, or file: resource prefix accordingly.";
                throw new ConfigurationException(msg);
            }
        } else {
            ini.loadFromPath(path);
        }

        return ini;
    }
}
