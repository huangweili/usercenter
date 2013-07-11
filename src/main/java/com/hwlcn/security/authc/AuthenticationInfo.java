package com.hwlcn.security.authc;

import com.hwlcn.security.subject.PrincipalCollection;

import java.io.Serializable;

public interface AuthenticationInfo extends Serializable {

    PrincipalCollection getPrincipals();

    Object getCredentials();

}
