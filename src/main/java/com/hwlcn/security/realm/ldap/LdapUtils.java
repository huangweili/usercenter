package com.hwlcn.security.realm.ldap;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.ldap.LdapContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public final class LdapUtils {

    private static final Logger log = LoggerFactory.getLogger(LdapUtils.class);

    public static void closeContext(LdapContext ctx) {
        try {
            if (ctx != null) {
                ctx.close();
            }
        } catch (NamingException e) {
            log.error("Exception while closing LDAP context. ", e);
        }
    }

    public static Collection<String> getAllAttributeValues(Attribute attr) throws NamingException {
        Set<String> values = new HashSet<String>();
        NamingEnumeration ne = null;
        try {
            ne = attr.getAll();
            while (ne.hasMore()) {
                String value = (String) ne.next();
                values.add(value);
            }
        } finally {
            closeEnumeration(ne);
        }

        return values;
    }

    public static void closeEnumeration(NamingEnumeration ne) {
        try {
            if (ne != null) {
                ne.close();
            }
        } catch (NamingException e) {
            log.error("Exception while closing NamingEnumeration: ", e);
        }
    }

}
