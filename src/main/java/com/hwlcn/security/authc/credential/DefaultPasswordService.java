
package com.hwlcn.security.authc.credential;

import com.hwlcn.security.crypto.hash.DefaultHashService;
import com.hwlcn.security.crypto.hash.HashRequest;
import com.hwlcn.security.crypto.hash.HashService;
import com.hwlcn.security.crypto.hash.format.*;
import com.hwlcn.security.util.ByteSource;
import com.hwlcn.security.crypto.hash.Hash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class DefaultPasswordService implements HashingPasswordService {

    public static final String DEFAULT_HASH_ALGORITHM = "SHA-256";
    public static final int DEFAULT_HASH_ITERATIONS = 500000;

    private static final Logger log = LoggerFactory.getLogger(DefaultPasswordService.class);

    private HashService hashService;
    private HashFormat hashFormat;
    private HashFormatFactory hashFormatFactory;

    private volatile boolean hashFormatWarned;

    public DefaultPasswordService() {
        this.hashFormatWarned = false;

        DefaultHashService hashService = new DefaultHashService();
        hashService.setHashAlgorithmName(DEFAULT_HASH_ALGORITHM);
        hashService.setHashIterations(DEFAULT_HASH_ITERATIONS);
        hashService.setGeneratePublicSalt(true);
        this.hashService = hashService;

        this.hashFormat = new SecurityCryptFormat();
        this.hashFormatFactory = new DefaultHashFormatFactory();
    }

    public String encryptPassword(Object plaintext) {
        Hash hash = hashPassword(plaintext);
        checkHashFormatDurability();
        return this.hashFormat.format(hash);
    }

    public Hash hashPassword(Object plaintext) {
        ByteSource plaintextBytes = createByteSource(plaintext);
        if (plaintextBytes == null || plaintextBytes.isEmpty()) {
            return null;
        }
        HashRequest request = createHashRequest(plaintextBytes);
        return hashService.computeHash(request);
    }

    public boolean passwordsMatch(Object plaintext, Hash saved) {
        ByteSource plaintextBytes = createByteSource(plaintext);

        if (saved == null || saved.isEmpty()) {
            return plaintextBytes == null || plaintextBytes.isEmpty();
        } else {
            if (plaintextBytes == null || plaintextBytes.isEmpty()) {
                return false;
            }
        }

        HashRequest request = buildHashRequest(plaintextBytes, saved);

        Hash computed = this.hashService.computeHash(request);

        return saved.equals(computed);
    }

    protected void checkHashFormatDurability() {

        if (!this.hashFormatWarned) {

            HashFormat format = this.hashFormat;

            if (!(format instanceof ParsableHashFormat) && log.isWarnEnabled()) {
                String msg = "The configured hashFormat instance [" + format.getClass().getName() + "] is not a " +
                        ParsableHashFormat.class.getName() + " implementation.  This is " +
                        "required if you wish to support backwards compatibility for saved password checking (almost " +
                        "always desirable).  Without a " + ParsableHashFormat.class.getSimpleName() + " instance, " +
                        "any hashService configuration changes will break previously hashed/saved passwords.";
                log.warn(msg);
                this.hashFormatWarned = true;
            }
        }
    }

    protected HashRequest createHashRequest(ByteSource plaintext) {
        return new HashRequest.Builder().setSource(plaintext).build();
    }

    protected ByteSource createByteSource(Object o) {
        return ByteSource.Util.bytes(o);
    }

    public boolean passwordsMatch(Object submittedPlaintext, String saved) {
        ByteSource plaintextBytes = createByteSource(submittedPlaintext);

        if (saved == null || saved.length() == 0) {
            return plaintextBytes == null || plaintextBytes.isEmpty();
        } else {
            if (plaintextBytes == null || plaintextBytes.isEmpty()) {
                return false;
            }
        }

        HashFormat discoveredFormat = this.hashFormatFactory.getInstance(saved);

        if (discoveredFormat != null && discoveredFormat instanceof ParsableHashFormat) {

            ParsableHashFormat parsableHashFormat = (ParsableHashFormat)discoveredFormat;
            Hash savedHash = parsableHashFormat.parse(saved);

            return passwordsMatch(submittedPlaintext, savedHash);
        }

        HashRequest request = createHashRequest(plaintextBytes);
        Hash computed = this.hashService.computeHash(request);
        String formatted = this.hashFormat.format(computed);

        return saved.equals(formatted);
    }

    protected HashRequest buildHashRequest(ByteSource plaintext, Hash saved) {
        return new HashRequest.Builder().setSource(plaintext)
                .setAlgorithmName(saved.getAlgorithmName())
                .setSalt(saved.getSalt())
                .setIterations(saved.getIterations())
                .build();
    }

    public HashService getHashService() {
        return hashService;
    }

    public void setHashService(HashService hashService) {
        this.hashService = hashService;
    }

    public HashFormat getHashFormat() {
        return hashFormat;
    }

    public void setHashFormat(HashFormat hashFormat) {
        this.hashFormat = hashFormat;
    }

    public HashFormatFactory getHashFormatFactory() {
        return hashFormatFactory;
    }

    public void setHashFormatFactory(HashFormatFactory hashFormatFactory) {
        this.hashFormatFactory = hashFormatFactory;
    }
}
