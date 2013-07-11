package com.hwlcn.security.authc;

import java.io.Serializable;


public interface AuthenticationToken extends Serializable {

    Object getPrincipal();


    Object getCredentials();

}
