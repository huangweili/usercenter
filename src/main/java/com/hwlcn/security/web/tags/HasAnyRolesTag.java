package com.hwlcn.security.web.tags;


import com.hwlcn.security.subject.Subject;

public class HasAnyRolesTag extends RoleTag {


    private static final String ROLE_NAMES_DELIMETER = ",";

    public HasAnyRolesTag() {
    }

    protected boolean showTagBody(String roleNames) {
        boolean hasAnyRole = false;
        Subject subject = getSubject();
        if (subject != null) {
            for (String role : roleNames.split(ROLE_NAMES_DELIMETER)) {

                if (subject.hasRole(role.trim())) {
                    hasAnyRole = true;
                    break;
                }
            }
        }
        return hasAnyRole;
    }
}
