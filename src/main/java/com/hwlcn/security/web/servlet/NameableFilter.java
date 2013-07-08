package com.hwlcn.security.web.servlet;

import com.hwlcn.security.util.Nameable;

import javax.servlet.FilterConfig;

public abstract class NameableFilter extends AbstractFilter implements Nameable {

    private String name;

    protected String getName() {
        if (this.name == null) {
            FilterConfig config = getFilterConfig();
            if (config != null) {
                this.name = config.getFilterName();
            }
        }

        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    protected StringBuilder toStringBuilder() {
        String name = getName();
        if (name == null) {
            return super.toStringBuilder();
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append(name);
            return sb;
        }
    }
}
