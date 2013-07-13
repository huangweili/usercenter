package com.hwlcn.security.jndi;

import javax.naming.Context;
import javax.naming.NamingException;


public interface JndiCallback {

    Object doInContext(Context ctx) throws NamingException;

}
