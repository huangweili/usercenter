package com.hwlcn.security.web.tags;

public class LacksPermissionTag extends PermissionTag {
    public LacksPermissionTag() {
    }

    protected boolean showTagBody(String p) {
        return !isPermitted(p);
    }

}
