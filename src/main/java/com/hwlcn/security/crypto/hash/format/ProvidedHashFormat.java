
package com.hwlcn.security.crypto.hash.format;


public enum ProvidedHashFormat {


    HEX(HexFormat.class),


    BASE64(Base64Format.class),


    Hwlcn(SecurityCryptFormat.class);

    private final Class<? extends HashFormat> clazz;

    private ProvidedHashFormat(Class<? extends HashFormat> clazz) {
        this.clazz = clazz;
    }

    Class<? extends HashFormat> getHashFormatClass() {
        return this.clazz;
    }

    public static ProvidedHashFormat byId(String id) {
        if (id == null) {
            return null;
        }
        try {
            return valueOf(id.toUpperCase());
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

}
