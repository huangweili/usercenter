package com.hwlcn.security.web.env;


import com.hwlcn.security.config.ResourceConfigurable;
import com.hwlcn.security.util.StringUtils;

public abstract class ResourceBasedWebEnvironment extends DefaultWebEnvironment implements ResourceConfigurable {

    private String[] configLocations;

    public String[] getConfigLocations() {
        return configLocations;
    }

    public void setConfigLocations(String locations) {
        if (!StringUtils.hasText(locations)) {
            throw new IllegalArgumentException("Null/empty locations argument not allowed.");
        }
        String[] arr = StringUtils.split(locations);
        setConfigLocations(arr);
    }

    public void setConfigLocations(String[] configLocations) {
        this.configLocations = configLocations;
    }

}
