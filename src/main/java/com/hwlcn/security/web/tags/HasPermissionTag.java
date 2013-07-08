package com.hwlcn.security.web.tags;


public class HasPermissionTag extends PermissionTag {

    public HasPermissionTag() {
    }

    protected boolean showTagBody(String p) {
        return isPermitted(p);
    }

}
