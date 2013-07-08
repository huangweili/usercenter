package com.hwlcn.security.web.tags;

public class HasRoleTag extends RoleTag {


    public HasRoleTag() {
    }

    protected boolean showTagBody(String roleName) {
        return getSubject() != null && getSubject().hasRole(roleName);
    }

}
