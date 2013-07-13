package com.hwlcn.security.subject;

import java.util.Collection;


public interface MutablePrincipalCollection extends PrincipalCollection {

    void add(Object principal, String realmName);

    void addAll(Collection principals, String realmName);

    void addAll(PrincipalCollection principals);

    void clear();
}
