package com.hwlcn.security.web.config;

import com.hwlcn.security.config.Ini;
import com.hwlcn.security.config.IniSecurityManagerFactory;
import com.hwlcn.security.mgt.SecurityManager;
import com.hwlcn.security.web.filter.mgt.DefaultFilter;
import com.hwlcn.security.web.mgt.DefaultWebSecurityManager;

import javax.servlet.Filter;
import java.util.Map;

public class WebIniSecurityManagerFactory extends IniSecurityManagerFactory {

    public WebIniSecurityManagerFactory() {
        super();
    }

    public WebIniSecurityManagerFactory(Ini config) {
        super(config);
    }


    @Override
    protected SecurityManager createDefaultInstance() {
        return new DefaultWebSecurityManager();
    }

    @SuppressWarnings({"unchecked"})
    @Override
    protected Map<String, ?> createDefaults(Ini ini, Ini.Section mainSection) {
        Map defaults = super.createDefaults(ini, mainSection);
        Map<String, Filter> defaultFilters = DefaultFilter.createInstanceMap(null);
        defaults.putAll(defaultFilters);
        return defaults;
    }
}
