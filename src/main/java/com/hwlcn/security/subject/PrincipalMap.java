package com.hwlcn.security.subject;

import java.util.Map;


public interface PrincipalMap extends PrincipalCollection, Map<String,Object> {

    Map<String,Object> getRealmPrincipals(String realmName);

    Map<String,Object> setRealmPrincipals(String realmName, Map<String, Object> principals);

    Object setRealmPrincipal(String realmName, String principalName, Object principal);

    Object getRealmPrincipal(String realmName, String realmPrincipal);

    Object removeRealmPrincipal(String realmName, String principalName);

}
