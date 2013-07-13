package com.hwlcn.security.authz;

import com.hwlcn.security.subject.PrincipalCollection;

import java.util.Collection;
import java.util.List;


public interface Authorizer {

    boolean isPermitted(PrincipalCollection principals, String permission);
    boolean isPermitted(PrincipalCollection subjectPrincipal, Permission permission);
    boolean[] isPermitted(PrincipalCollection subjectPrincipal, String... permissions);

    boolean[] isPermitted(PrincipalCollection subjectPrincipal, List<Permission> permissions);

    boolean isPermittedAll(PrincipalCollection subjectPrincipal, String... permissions);

    boolean isPermittedAll(PrincipalCollection subjectPrincipal, Collection<Permission> permissions);

    void checkPermission(PrincipalCollection subjectPrincipal, String permission) throws AuthorizationException;

    void checkPermission(PrincipalCollection subjectPrincipal, Permission permission) throws AuthorizationException;

    void checkPermissions(PrincipalCollection subjectPrincipal, String... permissions) throws AuthorizationException;

    void checkPermissions(PrincipalCollection subjectPrincipal, Collection<Permission> permissions) throws AuthorizationException;

    boolean hasRole(PrincipalCollection subjectPrincipal, String roleIdentifier);

    boolean[] hasRoles(PrincipalCollection subjectPrincipal, List<String> roleIdentifiers);

    boolean hasAllRoles(PrincipalCollection subjectPrincipal, Collection<String> roleIdentifiers);

    void checkRole(PrincipalCollection subjectPrincipal, String roleIdentifier) throws AuthorizationException;

    void checkRoles(PrincipalCollection subjectPrincipal, Collection<String> roleIdentifiers) throws AuthorizationException;

    void checkRoles(PrincipalCollection subjectPrincipal, String... roleIdentifiers) throws AuthorizationException;
    
}

