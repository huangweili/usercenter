package com.hwlcn.security.crypto.hash;

import com.hwlcn.security.codec.Base64;
import com.hwlcn.security.codec.CodecException;
import com.hwlcn.security.codec.CodecSupport;
import com.hwlcn.security.codec.Hex;
import com.hwlcn.security.crypto.UnknownAlgorithmException;
import com.hwlcn.security.util.ByteSource;
import com.hwlcn.security.util.StringUtils;

import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


public class SimpleHash extends CodecSupport implements Hash, Serializable {

    private static final int DEFAULT_ITERATIONS = 1;


    private final String algorithmName;


    private byte[] bytes;


    private ByteSource salt;


    private int iterations;


    private transient String hexEncoded = null;


    private transient String base64Encoded = null;


    public SimpleHash(String algorithmName) {
        this.algorithmName = algorithmName;
        this.iterations = DEFAULT_ITERATIONS;
    }


    public SimpleHash(String algorithmName, Object source) throws CodecException, UnknownAlgorithmException {
        this(algorithmName, source, null, DEFAULT_ITERATIONS);
    }


    public SimpleHash(String algorithmName, Object source, Object salt) throws CodecException, UnknownAlgorithmException {
        this(algorithmName, source, salt, DEFAULT_ITERATIONS);
    }


    public SimpleHash(String algorithmName, Object source, Object salt, int hashIterations)
            throws CodecException, UnknownAlgorithmException {
        if (!StringUtils.hasText(algorithmName)) {
            throw new NullPointerException("algorithmName argument cannot be null or empty.");
        }
        this.algorithmName = algorithmName;
        this.iterations = Math.max(DEFAULT_ITERATIONS, hashIterations);
        ByteSource saltBytes = null;
        if (salt != null) {
            saltBytes = convertSaltToBytes(salt);
            this.salt = saltBytes;
        }
        ByteSource sourceBytes = convertSourceToBytes(source);
        hash(sourceBytes, saltBytes, hashIterations);
    }


    protected ByteSource convertSourceToBytes(Object source) {
        return toByteSource(source);
    }


    protected ByteSource convertSaltToBytes(Object salt) {
        return toByteSource(salt);
    }

    protected ByteSource toByteSource(Object o) {
        if (o == null) {
            return null;
        }
        if (o instanceof ByteSource) {
            return (ByteSource) o;
        }
        byte[] bytes = toBytes(o);
        return ByteSource.Util.bytes(bytes);
    }

    private void hash(ByteSource source, ByteSource salt, int hashIterations) throws CodecException, UnknownAlgorithmException {
        byte[] saltBytes = salt != null ? salt.getBytes() : null;
        byte[] hashedBytes = hash(source.getBytes(), saltBytes, hashIterations);
        setBytes(hashedBytes);
    }


    public String getAlgorithmName() {
        return this.algorithmName;
    }

    public ByteSource getSalt() {
        return this.salt;
    }

    public int getIterations() {
        return this.iterations;
    }

    public byte[] getBytes() {
        return this.bytes;
    }


    public void setBytes(byte[] alreadyHashedBytes) {
        this.bytes = alreadyHashedBytes;
        this.hexEncoded = null;
        this.base64Encoded = null;
    }


    public void setIterations(int iterations) {
        this.iterations = Math.max(DEFAULT_ITERATIONS, iterations);
    }


    public void setSalt(ByteSource salt) {
        this.salt = salt;
    }


    protected MessageDigest getDigest(String algorithmName) throws UnknownAlgorithmException {
        try {
            return MessageDigest.getInstance(algorithmName);
        } catch (NoSuchAlgorithmException e) {
            String msg = "No native '" + algorithmName + "' MessageDigest instance available on the current JVM.";
            throw new UnknownAlgorithmException(msg, e);
        }
    }


    protected byte[] hash(byte[] bytes) throws UnknownAlgorithmException {
        return hash(bytes, null, DEFAULT_ITERATIONS);
    }


    protected byte[] hash(byte[] bytes, byte[] salt) throws UnknownAlgorithmException {
        return hash(bytes, salt, DEFAULT_ITERATIONS);
    }


    protected byte[] hash(byte[] bytes, byte[] salt, int hashIterations) throws UnknownAlgorithmException {
        MessageDigest digest = getDigest(getAlgorithmName());
        if (salt != null) {
            digest.reset();
            digest.update(salt);
        }
        byte[] hashed = digest.digest(bytes);
        int iterations = hashIterations - DEFAULT_ITERATIONS;

        for (int i = 0; i < iterations; i++) {
            digest.reset();
            hashed = digest.digest(hashed);
        }
        return hashed;
    }

    public boolean isEmpty() {
        return this.bytes == null || this.bytes.length == 0;
    }


    public String toHex() {
        if (this.hexEncoded == null) {
            this.hexEncoded = Hex.encodeToString(getBytes());
        }
        return this.hexEncoded;
    }


    public String toBase64() {
        if (this.base64Encoded == null) {

            this.base64Encoded = Base64.encodeToString(getBytes());
        }
        return this.base64Encoded;
    }


    public String toString() {
        return toHex();
    }


    public boolean equals(Object o) {
        if (o instanceof Hash) {
            Hash other = (Hash) o;
            return Arrays.equals(getBytes(), other.getBytes());
        }
        return false;
    }

    public int hashCode() {
        if (this.bytes == null || this.bytes.length == 0) {
            return 0;
        }
        return Arrays.hashCode(this.bytes);
    }
}
