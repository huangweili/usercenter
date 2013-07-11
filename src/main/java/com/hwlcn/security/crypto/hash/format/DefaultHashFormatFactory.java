
package com.hwlcn.security.crypto.hash.format;

import com.hwlcn.security.util.StringUtils;
import com.hwlcn.security.util.UnknownClassException;
import com.hwlcn.security.util.ClassUtils;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class DefaultHashFormatFactory implements HashFormatFactory {

    private Map<String, String> formatClassNames;

    private Set<String> searchPackages;

    public DefaultHashFormatFactory() {
        this.searchPackages = new HashSet<String>();
        this.formatClassNames = new HashMap<String, String>();
    }


    public Map<String, String> getFormatClassNames() {
        return formatClassNames;
    }


    public void setFormatClassNames(Map<String, String> formatClassNames) {
        this.formatClassNames = formatClassNames;
    }


    public Set<String> getSearchPackages() {
        return searchPackages;
    }


    public void setSearchPackages(Set<String> searchPackages) {
        this.searchPackages = searchPackages;
    }

    public HashFormat getInstance(String in) {
        if (in == null) {
            return null;
        }

        HashFormat hashFormat = null;
        Class clazz = null;


        if (in.startsWith(ModularCryptFormat.TOKEN_DELIMITER)) {

            String test = in.substring(ModularCryptFormat.TOKEN_DELIMITER.length());
            String[] tokens = test.split("\\" + ModularCryptFormat.TOKEN_DELIMITER);

            String possibleMcfId = (tokens != null && tokens.length > 0) ? tokens[0] : null;
            if (possibleMcfId != null) {
                clazz = getHashFormatClass(possibleMcfId);
            }
        }

        if (clazz == null) {
            clazz = getHashFormatClass(in);
        }

        if (clazz != null) {
            hashFormat = newHashFormatInstance(clazz);
        }

        return hashFormat;
    }


    protected Class getHashFormatClass(String token) {

        Class clazz = null;


        if (this.formatClassNames != null) {
            String value = this.formatClassNames.get(token);
            if (value != null) {
                clazz = lookupHashFormatClass(value);
            }
        }

        if (clazz == null) {
            ProvidedHashFormat provided = ProvidedHashFormat.byId(token);
            if (provided != null) {
                clazz = provided.getHashFormatClass();
            }
        }

        if (clazz == null) {
            clazz = lookupHashFormatClass(token);
        }

        if (clazz == null) {
            if (this.searchPackages != null) {
                for (String packageName : this.searchPackages) {
                    clazz = getHashFormatClass(packageName, token);
                    if (clazz != null) {
                        break;
                    }
                }
            }
        }

        if (clazz != null) {
            assertHashFormatImpl(clazz);
        }

        return clazz;
    }

    protected Class getHashFormatClass(String packageName, String token) {
        String test = token;
        Class clazz = null;
        String pkg = packageName == null ? "" : packageName;

        clazz = lookupHashFormatClass(test);

        if (clazz == null) {
            test = pkg + "." + token;
            clazz = lookupHashFormatClass(test);
        }

        if (clazz == null) {
            test = pkg + "." + StringUtils.uppercaseFirstChar(token) + "Format";
            clazz = lookupHashFormatClass(test);
        }

        if (clazz == null) {
            test = pkg + "." + token + "Format";
            clazz = lookupHashFormatClass(test);
        }

        if (clazz == null) {
            test = pkg + "." + StringUtils.uppercaseFirstChar(token) + "HashFormat";
            clazz = lookupHashFormatClass(test);
        }

        if (clazz == null) {
            test = pkg + "." + token + "HashFormat";
            clazz = lookupHashFormatClass(test);
        }

        if (clazz == null) {
            test = pkg + "." + StringUtils.uppercaseFirstChar(token) + "CryptFormat";
            clazz = lookupHashFormatClass(test);
        }

        if (clazz == null) {
            test = pkg + "." + token + "CryptFormat";
            clazz = lookupHashFormatClass(test);
        }

        if (clazz == null) {
            return null;
        }

        assertHashFormatImpl(clazz);

        return clazz;
    }

    protected Class lookupHashFormatClass(String name) {
        try {
            return ClassUtils.forName(name);
        } catch (UnknownClassException ignored) {
        }

        return null;
    }

    protected final void assertHashFormatImpl(Class clazz) {
        if (!HashFormat.class.isAssignableFrom(clazz) || clazz.isInterface()) {
            throw new IllegalArgumentException("Discovered class [" + clazz.getName() + "] is not a " +
                    HashFormat.class.getName() + " implementation.");
        }

    }

    protected final HashFormat newHashFormatInstance(Class clazz) {
        assertHashFormatImpl(clazz);
        return (HashFormat) ClassUtils.newInstance(clazz);
    }
}
