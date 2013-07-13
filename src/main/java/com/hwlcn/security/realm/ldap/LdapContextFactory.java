package com.hwlcn.security.realm.ldap;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

public interface LdapContextFactory {


    LdapContext getSystemLdapContext() throws NamingException;


    LdapContext getLdapContext(Object principal, Object credentials) throws NamingException;
    
}
