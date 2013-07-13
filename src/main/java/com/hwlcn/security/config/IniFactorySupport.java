package com.hwlcn.security.config;

import com.hwlcn.security.io.ResourceUtils;
import com.hwlcn.security.util.AbstractFactory;
import com.hwlcn.security.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public abstract class IniFactorySupport<T> extends AbstractFactory<T> {

    public static final String DEFAULT_INI_RESOURCE_PATH = "classpath:security.ini";

    private static transient final Logger log = LoggerFactory.getLogger(IniFactorySupport.class);

    private Ini ini;

    protected IniFactorySupport() {
    }

    protected IniFactorySupport(Ini ini) {
        this.ini = ini;
    }

    public Ini getIni() {
        return ini;
    }

    public void setIni(Ini ini) {
        this.ini = ini;
    }


    public static Ini loadDefaultClassPathIni() {
        Ini ini = null;
        if (ResourceUtils.resourceExists(DEFAULT_INI_RESOURCE_PATH)) {
            if (log.isDebugEnabled()) {
                log.debug("Found shiro.ini at the root of the classpath.");
            }
            ini = new Ini();
            ini.loadFromPath(DEFAULT_INI_RESOURCE_PATH);
            if (CollectionUtils.isEmpty(ini)) {
                if (log.isWarnEnabled()) {
                    log.warn("shiro.ini found at the root of the classpath, but it did not contain any data.");
                }
            }
        }
        return ini;
    }


    protected Ini resolveIni() {
        Ini ini = getIni();
        if (CollectionUtils.isEmpty(ini)) {
            log.debug("Null or empty Ini instance.  Falling back to the default {} file.", DEFAULT_INI_RESOURCE_PATH);
            ini = loadDefaultClassPathIni();
        }
        return ini;
    }


    public T createInstance() {
        Ini ini = resolveIni();

        T instance;

        if (CollectionUtils.isEmpty(ini)) {
            if(log.isDebugEnabled()){
            log.debug("No populated Ini available.  Creating a default instance.");
            }
            instance = createDefaultInstance();
            if (instance == null) {
                String msg = getClass().getName() + " implementation did not return a default instance in " +
                        "the event of a null/empty Ini configuration.  This is required to support the " +
                        "Factory interface.  Please check your implementation.";
                throw new IllegalStateException(msg);
            }
        } else {
            if(log.isDebugEnabled()){
            log.debug("Creating instance from Ini [" + ini + "]");
            }
            instance = createInstance(ini);
            if (instance == null) {
                String msg = getClass().getName() + " implementation did not return a constructed instance from " +
                        "the createInstance(Ini) method implementation.";
                throw new IllegalStateException(msg);
            }
        }

        return instance;
    }

    protected abstract T createInstance(Ini ini);

    protected abstract T createDefaultInstance();
}
