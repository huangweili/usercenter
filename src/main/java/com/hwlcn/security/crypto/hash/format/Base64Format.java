
package com.hwlcn.security.crypto.hash.format;

import com.hwlcn.security.crypto.hash.Hash;

public class Base64Format implements HashFormat {

    public String format(Hash hash) {
        return hash != null ? hash.toBase64() : null;
    }
}
