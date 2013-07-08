package com.hwlcn.security.crypto;

import javax.crypto.KeyGenerator;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public abstract class AbstractSymmetricCipherService extends JcaCipherService {

    protected AbstractSymmetricCipherService(String algorithmName) {
        super(algorithmName);
    }


    public Key generateNewKey() {
        return generateNewKey(getKeySize());
    }

    public Key generateNewKey(int keyBitSize) {
        KeyGenerator kg;
        try {
            kg = KeyGenerator.getInstance(getAlgorithmName());
        } catch (NoSuchAlgorithmException e) {
            String msg = "Unable to acquire " + getAlgorithmName() + " algorithm.  This is required to function.";
            throw new IllegalStateException(msg, e);
        }
        kg.init(keyBitSize);
        return kg.generateKey();
    }

}
