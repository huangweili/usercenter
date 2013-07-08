package com.hwlcn.security.config;

import com.hwlcn.security.mgt.DefaultSecurityManager;
import com.hwlcn.security.mgt.RealmSecurityManager;
import com.hwlcn.security.mgt.SecurityManager;
import com.hwlcn.security.realm.Realm;
import com.hwlcn.security.realm.RealmFactory;
import com.hwlcn.security.realm.text.IniRealm;
import com.hwlcn.security.util.CollectionUtils;
import com.hwlcn.security.util.LifecycleUtils;
import com.hwlcn.security.util.Nameable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class IniSecurityManagerFactory extends IniFactorySupport<com.hwlcn.security.mgt.SecurityManager> {

    public static final String MAIN_SECTION_NAME = "main";

    public static final String SECURITY_MANAGER_NAME = "securityManager";
    public static final String INI_REALM_NAME = "iniRealm";

    private static transient final Logger log = LoggerFactory.getLogger(IniSecurityManagerFactory.class);

    private ReflectionBuilder builder;


    public IniSecurityManagerFactory() {
    }

    public IniSecurityManagerFactory(Ini config) {
        setIni(config);
    }

    public IniSecurityManagerFactory(String iniResourcePath) {
        this(Ini.fromResourcePath(iniResourcePath));
    }

    public Map<String, ?> getBeans() {
        return this.builder != null ? Collections.unmodifiableMap(builder.getObjects()) : null;
    }

    private SecurityManager getSecurityManagerBean() {
        return builder.getBean(SECURITY_MANAGER_NAME, SecurityManager.class);
    }

    protected SecurityManager createDefaultInstance() {
        return new DefaultSecurityManager();
    }

    protected SecurityManager createInstance(Ini ini) {
        if (CollectionUtils.isEmpty(ini)) {
            throw new NullPointerException("Ini argument cannot be null or empty.");
        }
        SecurityManager securityManager = createSecurityManager(ini);
        if (securityManager == null) {
            String msg = SecurityManager.class + " instance cannot be null.";
            throw new ConfigurationException(msg);
        }
        return securityManager;
    }

    private SecurityManager createSecurityManager(Ini ini) {
        Ini.Section mainSection = ini.getSection(MAIN_SECTION_NAME);
        if (CollectionUtils.isEmpty(mainSection)) {

            mainSection = ini.getSection(Ini.DEFAULT_SECTION_NAME);
        }
        return createSecurityManager(ini, mainSection);
    }

    protected boolean isAutoApplyRealms(SecurityManager securityManager) {
        boolean autoApply = true;
        if (securityManager instanceof RealmSecurityManager) {
            RealmSecurityManager realmSecurityManager = (RealmSecurityManager) securityManager;
            Collection<Realm> realms = realmSecurityManager.getRealms();
            if (!CollectionUtils.isEmpty(realms)) {
                log.info("Realms have been explicitly set on the SecurityManager instance - auto-setting of " +
                        "realms will not occur.");
                autoApply = false;
            }
        }
        return autoApply;
    }

    @SuppressWarnings({"unchecked"})
    private SecurityManager createSecurityManager(Ini ini, Ini.Section mainSection) {

        Map<String, ?> defaults = createDefaults(ini, mainSection);
        Map<String, ?> objects = buildInstances(mainSection, defaults);

        SecurityManager securityManager = getSecurityManagerBean();

        boolean autoApplyRealms = isAutoApplyRealms(securityManager);

        if (autoApplyRealms) {
            //realms and realm factory might have been created - pull them out first so we can
            //initialize the securityManager:
            Collection<Realm> realms = getRealms(objects);
            //set them on the SecurityManager
            if (!CollectionUtils.isEmpty(realms)) {
                applyRealmsToSecurityManager(realms, securityManager);
            }
        }

        return securityManager;
    }

    protected Map<String, ?> createDefaults(Ini ini, Ini.Section mainSection) {
        Map<String, Object> defaults = new LinkedHashMap<String, Object>();

        SecurityManager securityManager = createDefaultInstance();
        defaults.put(SECURITY_MANAGER_NAME, securityManager);

        if (shouldImplicitlyCreateRealm(ini)) {
            Realm realm = createRealm(ini);
            if (realm != null) {
                defaults.put(INI_REALM_NAME, realm);
            }
        }

        return defaults;
    }

    private Map<String, ?> buildInstances(Ini.Section section, Map<String, ?> defaults) {
        this.builder = new ReflectionBuilder(defaults);
        return this.builder.buildObjects(section);
    }

    private void addToRealms(Collection<Realm> realms, RealmFactory factory) {
        LifecycleUtils.init(factory);
        Collection<Realm> factoryRealms = factory.getRealms();
        if (!CollectionUtils.isEmpty(factoryRealms)) {
            realms.addAll(factoryRealms);
        }
    }

    private Collection<Realm> getRealms(Map<String, ?> instances) {


        List<Realm> realms = new ArrayList<Realm>();

        for (Map.Entry<String, ?> entry : instances.entrySet()) {

            String name = entry.getKey();
            Object value = entry.getValue();

            if (value instanceof RealmFactory) {
                addToRealms(realms, (RealmFactory) value);
            } else if (value instanceof Realm) {
                Realm realm = (Realm) value;
                //set the name if null:
                String existingName = realm.getName();
                if (existingName == null || existingName.startsWith(realm.getClass().getName())) {
                    if (realm instanceof Nameable) {
                        ((Nameable) realm).setName(name);
                        log.debug("Applied name '{}' to Nameable realm instance {}", name, realm);
                    } else {
                        log.info("Realm does not implement the {} interface.  Configured name will not be applied.",
                                Nameable.class.getName());
                    }
                }
                realms.add(realm);
            }
        }

        return realms;
    }

    private void assertRealmSecurityManager(SecurityManager securityManager) {
        if (securityManager == null) {
            throw new NullPointerException("securityManager instance cannot be null");
        }
        if (!(securityManager instanceof RealmSecurityManager)) {
            String msg = "securityManager instance is not a " + RealmSecurityManager.class.getName() +
                    " instance.  This is required to access or configure realms on the instance.";
            throw new ConfigurationException(msg);
        }
    }

    protected void applyRealmsToSecurityManager(Collection<Realm> realms, SecurityManager securityManager) {
        assertRealmSecurityManager(securityManager);
        ((RealmSecurityManager) securityManager).setRealms(realms);
    }


    protected boolean shouldImplicitlyCreateRealm(Ini ini) {
        return !CollectionUtils.isEmpty(ini) &&
                (!CollectionUtils.isEmpty(ini.getSection(IniRealm.ROLES_SECTION_NAME)) ||
                        !CollectionUtils.isEmpty(ini.getSection(IniRealm.USERS_SECTION_NAME)));
    }


    protected Realm createRealm(Ini ini) {

        IniRealm realm = new IniRealm();
        realm.setName(INI_REALM_NAME);
        realm.setIni(ini);
        return realm;
    }
}