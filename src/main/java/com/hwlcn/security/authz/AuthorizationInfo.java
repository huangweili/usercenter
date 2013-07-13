package com.hwlcn.security.authz;

import java.io.Serializable;
import java.util.Collection;


public interface AuthorizationInfo extends Serializable {

    Collection<String> getRoles();

    Collection<String> getStringPermissions();

    Collection<Permission> getObjectPermissions();
}
