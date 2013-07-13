package com.hwlcn.security.crypto.hash;

import com.hwlcn.security.util.ByteSource;


public class SimpleHashRequest implements HashRequest {

    private final ByteSource source; //cannot be null - this is the source to hash.
    private final ByteSource salt; //null = no salt specified
    private final int iterations; //0 = not specified by the requestor; let the HashService decide.
    private final String algorithmName; //null = let the HashService decide.

    public SimpleHashRequest(String algorithmName, ByteSource source, ByteSource salt, int iterations) {
        if (source == null) {
            throw new NullPointerException("source argument cannot be null");
        }
        this.source = source;
        this.salt = salt;
        this.algorithmName = algorithmName;
        this.iterations = Math.max(0, iterations);
    }

    public ByteSource getSource() {
        return this.source;
    }

    public ByteSource getSalt() {
        return this.salt;
    }

    public int getIterations() {
        return iterations;
    }

    public String getAlgorithmName() {
        return algorithmName;
    }
}
