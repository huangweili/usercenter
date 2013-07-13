
package com.hwlcn.security.realm.jndi;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import com.hwlcn.security.realm.Realm;
import com.hwlcn.security.jndi.JndiLocator;
import com.hwlcn.security.realm.RealmFactory;
import com.hwlcn.security.util.StringUtils;


public class JndiRealmFactory extends JndiLocator implements RealmFactory {

    Collection<String> jndiNames = null;


    public Collection<String> getJndiNames() {
        return jndiNames;
    }


    public void setJndiNames(Collection<String> jndiNames) {
        this.jndiNames = jndiNames;
    }


    public void setJndiNames(String commaDelimited) throws IllegalStateException {
        String arg = StringUtils.clean(commaDelimited);
        if (arg == null) {
            String msg = "One or more comma-delimited jndi names must be specified for the " +
                    getClass().getName() + " to locate Realms.";
            throw new IllegalStateException(msg);
        }
        String[] names = StringUtils.tokenizeToStringArray(arg, ",");
        setJndiNames(Arrays.asList(names));
    }


    public Collection<Realm> getRealms() throws IllegalStateException {
        Collection<String> jndiNames = getJndiNames();
        if (jndiNames == null || jndiNames.isEmpty()) {
            String msg = "One or more jndi names must be specified for the " +
                    getClass().getName() + " to locate Realms.";
            throw new IllegalStateException(msg);
        }
        List<Realm> realms = new ArrayList<Realm>(jndiNames.size());
        for (String name : jndiNames) {
            try {
                Realm realm = (Realm) lookup(name, Realm.class);
                realms.add(realm);
            } catch (Exception e) {
                throw new IllegalStateException("Unable to look up realm with jndi name '" + name + "'.", e);
            }
        }
        return realms.isEmpty() ? null : realms;
    }
}
