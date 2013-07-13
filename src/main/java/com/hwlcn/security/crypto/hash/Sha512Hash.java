package com.hwlcn.security.crypto.hash;

import com.hwlcn.security.codec.Base64;
import com.hwlcn.security.codec.Hex;

public class Sha512Hash extends SimpleHash {
    public static final String ALGORITHM_NAME = "SHA-512";

    public Sha512Hash() {
        super(ALGORITHM_NAME);
    }

    public Sha512Hash(Object source) {
        super(ALGORITHM_NAME, source);
    }

    public Sha512Hash(Object source, Object salt) {
        super(ALGORITHM_NAME, source, salt);
    }

    public Sha512Hash(Object source, Object salt, int hashIterations) {
        super(ALGORITHM_NAME, source, salt, hashIterations);
    }

    public static Sha512Hash fromHexString(String hex) {
        Sha512Hash hash = new Sha512Hash();
        hash.setBytes(Hex.decode(hex));
        return hash;
    }

    public static Sha512Hash fromBase64String(String base64) {
        Sha512Hash hash = new Sha512Hash();
        hash.setBytes(Base64.decode(base64));
        return hash;
    }
}

