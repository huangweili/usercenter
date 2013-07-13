package com.hwlcn.security.crypto;

import com.hwlcn.security.util.ByteSource;

import java.security.SecureRandom;

public class SecureRandomNumberGenerator implements RandomNumberGenerator {

    protected static final int DEFAULT_NEXT_BYTES_SIZE = 16;

    private int defaultNextBytesSize;
    private SecureRandom secureRandom;

    public SecureRandomNumberGenerator() {
        this.defaultNextBytesSize = DEFAULT_NEXT_BYTES_SIZE;
        this.secureRandom = new SecureRandom();
    }

    public void setSeed(byte[] bytes) {
        this.secureRandom.setSeed(bytes);
    }

    public SecureRandom getSecureRandom() {
        return secureRandom;
    }

    public void setSecureRandom(SecureRandom random) throws NullPointerException {
        if (random == null) {
            throw new NullPointerException("SecureRandom argument cannot be null.");
        }
        this.secureRandom = random;
    }

    public int getDefaultNextBytesSize() {
        return defaultNextBytesSize;
    }

    public void setDefaultNextBytesSize(int defaultNextBytesSize) throws IllegalArgumentException {
        if (defaultNextBytesSize <= 0) {
            throw new IllegalArgumentException("size value must be a positive integer (1 or larger)");
        }
        this.defaultNextBytesSize = defaultNextBytesSize;
    }

    public ByteSource nextBytes() {
        return nextBytes(getDefaultNextBytesSize());
    }

    public ByteSource nextBytes(int numBytes) {
        if (numBytes <= 0) {
            throw new IllegalArgumentException("numBytes argument must be a positive integer (1 or larger)");
        }
        byte[] bytes = new byte[numBytes];
        this.secureRandom.nextBytes(bytes);
        return ByteSource.Util.bytes(bytes);
    }
}
