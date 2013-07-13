package com.hwlcn.security.crypto.hash;

import com.hwlcn.security.codec.Base64;
import com.hwlcn.security.codec.Hex;



public class Sha1Hash extends SimpleHash {

  public static final String ALGORITHM_NAME = "SHA-1";

    public Sha1Hash() {
        super(ALGORITHM_NAME);
    }

    public Sha1Hash(Object source) {
        super(ALGORITHM_NAME, source);
    }

    public Sha1Hash(Object source, Object salt) {
        super(ALGORITHM_NAME, source, salt);
    }

    public Sha1Hash(Object source, Object salt, int hashIterations) {
        super(ALGORITHM_NAME, source, salt, hashIterations);
    }

    public static Sha1Hash fromHexString(String hex) {
        Sha1Hash hash = new Sha1Hash();
        hash.setBytes(Hex.decode(hex));
        return hash;
    }

    public static Sha1Hash fromBase64String(String base64) {
        Sha1Hash hash = new Sha1Hash();
        hash.setBytes(Base64.decode(base64));
        return hash;
    }
}
