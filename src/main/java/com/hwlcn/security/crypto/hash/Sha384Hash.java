package com.hwlcn.security.crypto.hash;

import com.hwlcn.security.codec.Base64;
import com.hwlcn.security.codec.Hex;


public class Sha384Hash extends SimpleHash {

    public static final String ALGORITHM_NAME = "SHA-384";

    public Sha384Hash() {
        super(ALGORITHM_NAME);
    }

    public Sha384Hash(Object source) {
        super(ALGORITHM_NAME, source);
    }

    public Sha384Hash(Object source, Object salt) {
        super(ALGORITHM_NAME, source, salt);
    }

    public Sha384Hash(Object source, Object salt, int hashIterations) {
        super(ALGORITHM_NAME, source, salt, hashIterations);
    }

    public static Sha384Hash fromHexString(String hex) {
        Sha384Hash hash = new Sha384Hash();
        hash.setBytes(Hex.decode(hex));
        return hash;
    }

    public static Sha384Hash fromBase64String(String base64) {
        Sha384Hash hash = new Sha384Hash();
        hash.setBytes(Base64.decode(base64));
        return hash;
    }
}
