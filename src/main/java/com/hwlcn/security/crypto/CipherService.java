package com.hwlcn.security.crypto;

import com.hwlcn.security.util.ByteSource;

import java.io.InputStream;
import java.io.OutputStream;


public interface CipherService {

    ByteSource decrypt(byte[] encrypted, byte[] decryptionKey) throws CryptoException;

    void decrypt(InputStream in, OutputStream out, byte[] decryptionKey) throws CryptoException;

    ByteSource encrypt(byte[] raw, byte[] encryptionKey) throws CryptoException;

    void encrypt(InputStream in, OutputStream out, byte[] encryptionKey) throws CryptoException;

}
