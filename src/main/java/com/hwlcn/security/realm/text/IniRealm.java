package com.hwlcn.security.realm.text;

import com.hwlcn.security.util.CollectionUtils;
import com.hwlcn.security.config.Ini;
import com.hwlcn.security.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class IniRealm extends TextConfigurationRealm {

    public static final String USERS_SECTION_NAME = "users";
    public static final String ROLES_SECTION_NAME = "roles";

    private static transient final Logger log = LoggerFactory.getLogger(IniRealm.class);

    private String resourcePath;
    private Ini ini;

    public IniRealm() {
        super();
    }

    public IniRealm(Ini ini) {
        this();
        processDefinitions(ini);
    }

    public IniRealm(String resourcePath) {
        this();
        Ini ini = Ini.fromResourcePath(resourcePath);
        this.ini = ini;
        this.resourcePath = resourcePath;
        processDefinitions(ini);
    }

    public String getResourcePath() {
        return resourcePath;
    }

    public void setResourcePath(String resourcePath) {
        this.resourcePath = resourcePath;
    }

    public Ini getIni() {
        return ini;
    }

    public void setIni(Ini ini) {
        this.ini = ini;
    }

    @Override
    protected void onInit() {
        super.onInit();

        Ini ini = getIni();
        String resourcePath = getResourcePath();
                
        if (!CollectionUtils.isEmpty(this.users) || !CollectionUtils.isEmpty(this.roles)) {
            if (!CollectionUtils.isEmpty(ini)) {
                log.warn("Users or Roles are already populated.  Configured Ini instance will be ignored.");
            }
            if (StringUtils.hasText(resourcePath)) {
                log.warn("Users or Roles are already populated.  resourcePath '{}' will be ignored.", resourcePath);
            }
            
            log.debug("Instance is already populated with users or roles.  No additional user/role population " +
                    "will be performed.");
            return;
        }
        
        if (CollectionUtils.isEmpty(ini)) {
            log.debug("No INI instance configuration present.  Checking resourcePath...");
            
            if (StringUtils.hasText(resourcePath)) {
                log.debug("Resource path {} defined.  Creating INI instance.", resourcePath);
                ini = Ini.fromResourcePath(resourcePath);
                if (!CollectionUtils.isEmpty(ini)) {
                    setIni(ini);
                }
            }
        }
        
        if (CollectionUtils.isEmpty(ini)) {
            String msg = "Ini instance and/or resourcePath resulted in null or empty Ini configuration.  Cannot " +
                    "load account data.";
            throw new IllegalStateException(msg);
        }

        processDefinitions(ini);
    }

    private void processDefinitions(Ini ini) {
        if (CollectionUtils.isEmpty(ini)) {
            log.warn("{} defined, but the ini instance is null or empty.", getClass().getSimpleName());
            return;
        }

        Ini.Section rolesSection = ini.getSection(ROLES_SECTION_NAME);
        if (!CollectionUtils.isEmpty(rolesSection)) {
            log.debug("Discovered the [{}] section.  Processing...", ROLES_SECTION_NAME);
            processRoleDefinitions(rolesSection);
        }

        Ini.Section usersSection = ini.getSection(USERS_SECTION_NAME);
        if (!CollectionUtils.isEmpty(usersSection)) {
            log.debug("Discovered the [{}] section.  Processing...", USERS_SECTION_NAME);
            processUserDefinitions(usersSection);
        } else {
            log.info("{} defined, but there is no [{}] section defined.  This realm will not be populated with any " +
                    "users and it is assumed that they will be populated programatically.  Users must be defined " +
                    "for this Realm instance to be useful.", getClass().getSimpleName(), USERS_SECTION_NAME);
        }
    }
}
