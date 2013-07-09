
package com.hwlcn.security.crypto.hash.format;


public interface ModularCryptFormat extends HashFormat {

    public static final String TOKEN_DELIMITER = "$";


    String getId();
}
