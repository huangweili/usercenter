package com.hwlcn.security.web.tags;

public class LacksRoleTag extends RoleTag {

    public LacksRoleTag() {
    }

    protected boolean showTagBody(String roleName) {
        boolean hasRole = getSubject() != null && getSubject().hasRole(roleName);
        return !hasRole;
    }

}
