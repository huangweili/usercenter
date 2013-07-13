package com.hwlcn.security.realm.text;

import com.hwlcn.HwlcnException;
import com.hwlcn.security.io.ResourceUtils;
import com.hwlcn.security.util.Destroyable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class PropertiesRealm extends TextConfigurationRealm implements Destroyable, Runnable {

    private static final int DEFAULT_RELOAD_INTERVAL_SECONDS = 10;
    private static final String USERNAME_PREFIX = "user.";
    private static final String ROLENAME_PREFIX = "role.";
    private static final String DEFAULT_RESOURCE_PATH = "classpath:security-users.properties";

    private static final Logger log = LoggerFactory.getLogger(PropertiesRealm.class);

    protected ExecutorService scheduler = null;
    protected boolean useXmlFormat = false;
    protected String resourcePath = DEFAULT_RESOURCE_PATH;
    protected long fileLastModified;
    protected int reloadIntervalSeconds = DEFAULT_RELOAD_INTERVAL_SECONDS;

    public PropertiesRealm() {
        super();
    }

    public void setUseXmlFormat(boolean useXmlFormat) {
        this.useXmlFormat = useXmlFormat;
    }

    public void setResourcePath(String resourcePath) {
        this.resourcePath = resourcePath;
    }

    public void setReloadIntervalSeconds(int reloadIntervalSeconds) {
        this.reloadIntervalSeconds = reloadIntervalSeconds;
    }

    @Override
    public void onInit() {
        super.onInit();
        afterRoleCacheSet();
    }

    protected void afterRoleCacheSet() {
        loadProperties();
        if (this.resourcePath.startsWith(ResourceUtils.FILE_PREFIX) && scheduler == null) {
            startReloadThread();
        }
    }


    public void destroy() {
        try {
            if (scheduler != null) {
                scheduler.shutdown();
            }
        } catch (Exception e) {
            if (log.isInfoEnabled()) {
                log.info("Unable to cleanly shutdown Scheduler.  Ignoring (shutting down)...", e);
            }
        } finally {
            scheduler = null;
        }
    }

    protected void startReloadThread() {
        if (this.reloadIntervalSeconds > 0) {
            this.scheduler = Executors.newSingleThreadScheduledExecutor();
            ((ScheduledExecutorService) this.scheduler).scheduleAtFixedRate(this, reloadIntervalSeconds, reloadIntervalSeconds, TimeUnit.SECONDS);
        }
    }

    public void run() {
        try {
            reloadPropertiesIfNecessary();
        } catch (Exception e) {
            if (log.isErrorEnabled()) {
                log.error("Error while reloading property files for realm.", e);
            }
        }
    }

    private void loadProperties() {
        if (resourcePath == null || resourcePath.length() == 0) {
            throw new IllegalStateException("The resourcePath property is not set.  " +
                    "It must be set prior to this realm being initialized.");
        }

        if (log.isDebugEnabled()) {
            log.debug("Loading user security information from file [" + resourcePath + "]...");
        }

        Properties properties = loadProperties(resourcePath);
        createRealmEntitiesFromProperties(properties);
    }

    private Properties loadProperties(String resourcePath) {
        Properties props = new Properties();

        InputStream is = null;
        try {

            if (log.isDebugEnabled()) {
                log.debug("Opening input stream for path [" + resourcePath + "]...");
            }

            is = ResourceUtils.getInputStreamForPath(resourcePath);
            if (useXmlFormat) {

                if (log.isDebugEnabled()) {
                    log.debug("Loading properties from path [" + resourcePath + "] in XML format...");
                }

                props.loadFromXML(is);
            } else {

                if (log.isDebugEnabled()) {
                    log.debug("Loading properties from path [" + resourcePath + "]...");
                }

                props.load(is);
            }

        } catch (IOException e) {
            throw new HwlcnException("Error reading properties path [" + resourcePath + "].  " +
                    "Initializing of the realm from this file failed.", e);
        } finally {
            ResourceUtils.close(is);
        }

        return props;
    }


    private void reloadPropertiesIfNecessary() {
        if (isSourceModified()) {
            restart();
        }
    }

    private boolean isSourceModified() {
        return this.resourcePath.startsWith(ResourceUtils.FILE_PREFIX) && isFileModified();
    }

    private boolean isFileModified() {
        String fileNameWithoutPrefix = this.resourcePath.substring(this.resourcePath.indexOf(":") + 1);
        File propertyFile = new File(fileNameWithoutPrefix);
        long currentLastModified = propertyFile.lastModified();
        if (currentLastModified > this.fileLastModified) {
            this.fileLastModified = currentLastModified;
            return true;
        } else {
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    private void restart() {
        if (resourcePath == null || resourcePath.length() == 0) {
            throw new IllegalStateException("The resourcePath property is not set.  " +
                    "It must be set prior to this realm being initialized.");
        }

        if (log.isDebugEnabled()) {
            log.debug("Loading user security information from file [" + resourcePath + "]...");
        }

        try {
            destroy();
        } catch (Exception e) {
            //ignored
        }
        init();
    }

    @SuppressWarnings("unchecked")
    private void createRealmEntitiesFromProperties(Properties properties) {

        StringBuilder userDefs = new StringBuilder();
        StringBuilder roleDefs = new StringBuilder();

        Enumeration<String> propNames = (Enumeration<String>) properties.propertyNames();

        while (propNames.hasMoreElements()) {

            String key = propNames.nextElement().trim();
            String value = properties.getProperty(key).trim();
            if (log.isTraceEnabled()) {
                log.trace("Processing properties line - key: [" + key + "], value: [" + value + "].");
            }

            if (isUsername(key)) {
                String username = getUsername(key);
                userDefs.append(username).append(" = ").append(value).append("\n");
            } else if (isRolename(key)) {
                String rolename = getRolename(key);
                roleDefs.append(rolename).append(" = ").append(value).append("\n");
            } else {
                String msg = "Encountered unexpected key/value pair.  All keys must be prefixed with either '" +
                        USERNAME_PREFIX + "' or '" + ROLENAME_PREFIX + "'.";
                throw new IllegalStateException(msg);
            }
        }

        setUserDefinitions(userDefs.toString());
        setRoleDefinitions(roleDefs.toString());
        processDefinitions();
    }

    protected String getName(String key, String prefix) {
        return key.substring(prefix.length(), key.length());
    }

    protected boolean isUsername(String key) {
        return key != null && key.startsWith(USERNAME_PREFIX);
    }

    protected boolean isRolename(String key) {
        return key != null && key.startsWith(ROLENAME_PREFIX);
    }

    protected String getUsername(String key) {
        return getName(key, USERNAME_PREFIX);
    }

    protected String getRolename(String key) {
        return getName(key, ROLENAME_PREFIX);
    }
}
