
package com.hwlcn.security.crypto;

import com.hwlcn.security.util.ByteSource;
import com.hwlcn.security.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;


public abstract class JcaCipherService implements CipherService {


    private static final Logger log = LoggerFactory.getLogger(JcaCipherService.class);

    private static final int DEFAULT_KEY_SIZE = 128;

    private static final int DEFAULT_STREAMING_BUFFER_SIZE = 512;

    private static final int BITS_PER_BYTE = 8;

    private static final String RANDOM_NUM_GENERATOR_ALGORITHM_NAME = "SHA1PRNG";

    private String algorithmName;

    private int keySize;

    private int streamingBufferSize;

    private boolean generateInitializationVectors;
    private int initializationVectorSize;


    private SecureRandom secureRandom;


    protected JcaCipherService(String algorithmName) {
        if (!StringUtils.hasText(algorithmName)) {
            throw new IllegalArgumentException("algorithmName argument cannot be null or empty.");
        }
        this.algorithmName = algorithmName;
        this.keySize = DEFAULT_KEY_SIZE;
        this.initializationVectorSize = DEFAULT_KEY_SIZE; //default to same size as the key size (a common algorithm practice)
        this.streamingBufferSize = DEFAULT_STREAMING_BUFFER_SIZE;
        this.generateInitializationVectors = true;
    }


    public String getAlgorithmName() {
        return algorithmName;
    }


    public int getKeySize() {
        return keySize;
    }


    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    public boolean isGenerateInitializationVectors() {
        return generateInitializationVectors;
    }

    public void setGenerateInitializationVectors(boolean generateInitializationVectors) {
        this.generateInitializationVectors = generateInitializationVectors;
    }


    public int getInitializationVectorSize() {
        return initializationVectorSize;
    }


    public void setInitializationVectorSize(int initializationVectorSize) throws IllegalArgumentException {
        if (initializationVectorSize % BITS_PER_BYTE != 0) {
            String msg = "Initialization vector sizes are specified in bits, but must be a multiple of 8 so they " +
                    "can be easily represented as a byte array.";
            throw new IllegalArgumentException(msg);
        }
        this.initializationVectorSize = initializationVectorSize;
    }

    protected boolean isGenerateInitializationVectors(boolean streaming) {
        return isGenerateInitializationVectors();
    }

    public int getStreamingBufferSize() {
        return streamingBufferSize;
    }

    public void setStreamingBufferSize(int streamingBufferSize) {
        this.streamingBufferSize = streamingBufferSize;
    }


    public SecureRandom getSecureRandom() {
        return secureRandom;
    }


    public void setSecureRandom(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    protected static SecureRandom getDefaultSecureRandom() {
        try {
            return SecureRandom.getInstance(RANDOM_NUM_GENERATOR_ALGORITHM_NAME);
        } catch (java.security.NoSuchAlgorithmException e) {
            if (log.isDebugEnabled()) {
                log.debug("The SecureRandom SHA1PRNG algorithm is not available on the current platform.  Using the " +
                        "platform's default SecureRandom algorithm.", e);
            }
            return new SecureRandom();
        }
    }

    protected SecureRandom ensureSecureRandom() {
        SecureRandom random = getSecureRandom();
        if (random == null) {
            random = getDefaultSecureRandom();
        }
        return random;
    }


    protected String getTransformationString(boolean streaming) {
        return getAlgorithmName();
    }

    protected byte[] generateInitializationVector(boolean streaming) {
        int size = getInitializationVectorSize();
        if (size <= 0) {
            String msg = "initializationVectorSize property must be greater than zero.  This number is " +
                    "typically set in the " + CipherService.class.getSimpleName() + " subclass constructor.  " +
                    "Also check your configuration to ensure that if you are setting a value, it is positive.";
            throw new IllegalStateException(msg);
        }
        if (size % BITS_PER_BYTE != 0) {
            String msg = "initializationVectorSize property must be a multiple of 8 to represent as a byte array.";
            throw new IllegalStateException(msg);
        }
        int sizeInBytes = size / BITS_PER_BYTE;
        byte[] ivBytes = new byte[sizeInBytes];
        SecureRandom random = ensureSecureRandom();
        random.nextBytes(ivBytes);
        return ivBytes;
    }

    public ByteSource encrypt(byte[] plaintext, byte[] key) {
        byte[] ivBytes = null;
        boolean generate = isGenerateInitializationVectors(false);
        if (generate) {
            ivBytes = generateInitializationVector(false);
            if (ivBytes == null || ivBytes.length == 0) {
                throw new IllegalStateException("Initialization vector generation is enabled - generated vector" +
                        "cannot be null or empty.");
            }
        }
        return encrypt(plaintext, key, ivBytes, generate);
    }

    private ByteSource encrypt(byte[] plaintext, byte[] key, byte[] iv, boolean prependIv) throws CryptoException {

        final int MODE = javax.crypto.Cipher.ENCRYPT_MODE;

        byte[] output;

        if (prependIv && iv != null && iv.length > 0) {

            byte[] encrypted = crypt(plaintext, key, iv, MODE);

            output = new byte[iv.length + encrypted.length];


            System.arraycopy(iv, 0, output, 0, iv.length);


            System.arraycopy(encrypted, 0, output, iv.length, encrypted.length);
        } else {
            output = crypt(plaintext, key, iv, MODE);
        }

        if (log.isTraceEnabled()) {
            log.trace("Incoming plaintext of size " + (plaintext != null ? plaintext.length : 0) + ".  Ciphertext " +
                    "byte array is size " + (output != null ? output.length : 0));
        }

        return ByteSource.Util.bytes(output);
    }

    public ByteSource decrypt(byte[] ciphertext, byte[] key) throws CryptoException {

        byte[] encrypted = ciphertext;

        byte[] iv = null;

        if (isGenerateInitializationVectors(false)) {
            try {

                int ivSize = getInitializationVectorSize();
                int ivByteSize = ivSize / BITS_PER_BYTE;
                iv = new byte[ivByteSize];
                System.arraycopy(ciphertext, 0, iv, 0, ivByteSize);

                int encryptedSize = ciphertext.length - ivByteSize;
                encrypted = new byte[encryptedSize];
                System.arraycopy(ciphertext, ivByteSize, encrypted, 0, encryptedSize);
            } catch (Exception e) {
                String msg = "Unable to correctly extract the Initialization Vector or ciphertext.";
                throw new CryptoException(msg, e);
            }
        }

        return decrypt(encrypted, key, iv);
    }

    private ByteSource decrypt(byte[] ciphertext, byte[] key, byte[] iv) throws CryptoException {
        if (log.isTraceEnabled()) {
            log.trace("Attempting to decrypt incoming byte array of length " +
                    (ciphertext != null ? ciphertext.length : 0));
        }
        byte[] decrypted = crypt(ciphertext, key, iv, javax.crypto.Cipher.DECRYPT_MODE);
        return decrypted == null ? null : ByteSource.Util.bytes(decrypted);
    }


    private javax.crypto.Cipher newCipherInstance(boolean streaming) throws CryptoException {
        String transformationString = getTransformationString(streaming);
        try {
            return javax.crypto.Cipher.getInstance(transformationString);
        } catch (Exception e) {
            String msg = "Unable to acquire a Java JCA Cipher instance using " +
                    javax.crypto.Cipher.class.getName() + ".getInstance( \"" + transformationString + "\" ). " +
                    getAlgorithmName() + " under this configuration is required for the " +
                    getClass().getName() + " instance to function.";
            throw new CryptoException(msg, e);
        }
    }


    private byte[] crypt(byte[] bytes, byte[] key, byte[] iv, int mode) throws IllegalArgumentException, CryptoException {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("key argument cannot be null or empty.");
        }
        javax.crypto.Cipher cipher = initNewCipher(mode, key, iv, false);
        return crypt(cipher, bytes);
    }


    private byte[] crypt(javax.crypto.Cipher cipher, byte[] bytes) throws CryptoException {
        try {
            return cipher.doFinal(bytes);
        } catch (Exception e) {
            String msg = "Unable to execute 'doFinal' with cipher instance [" + cipher + "].";
            throw new CryptoException(msg, e);
        }
    }


    private void init(javax.crypto.Cipher cipher, int mode, Key key,
                      AlgorithmParameterSpec spec, SecureRandom random) throws CryptoException {
        try {
            if (random != null) {
                if (spec != null) {
                    cipher.init(mode, key, spec, random);
                } else {
                    cipher.init(mode, key, random);
                }
            } else {
                if (spec != null) {
                    cipher.init(mode, key, spec);
                } else {
                    cipher.init(mode, key);
                }
            }
        } catch (Exception e) {
            String msg = "Unable to init cipher instance.";
            throw new CryptoException(msg, e);
        }
    }


    public void encrypt(InputStream in, OutputStream out, byte[] key) throws CryptoException {
        byte[] iv = null;
        boolean generate = isGenerateInitializationVectors(true);
        if (generate) {
            iv = generateInitializationVector(true);
            if (iv == null || iv.length == 0) {
                throw new IllegalStateException("Initialization vector generation is enabled - generated vector" +
                        "cannot be null or empty.");
            }
        }
        encrypt(in, out, key, iv, generate);
    }

    private void encrypt(InputStream in, OutputStream out, byte[] key, byte[] iv, boolean prependIv) throws CryptoException {
        if (prependIv && iv != null && iv.length > 0) {
            try {
                out.write(iv);
            } catch (IOException e) {
                throw new CryptoException(e);
            }
        }

        crypt(in, out, key, iv, javax.crypto.Cipher.ENCRYPT_MODE);
    }

    public void decrypt(InputStream in, OutputStream out, byte[] key) throws CryptoException {
        decrypt(in, out, key, isGenerateInitializationVectors(true));
    }

    private void decrypt(InputStream in, OutputStream out, byte[] key, boolean ivPrepended) throws CryptoException {

        byte[] iv = null;
        if (ivPrepended) {
           int ivSize = getInitializationVectorSize();
            int ivByteSize = ivSize / BITS_PER_BYTE;
            iv = new byte[ivByteSize];
            int read;

            try {
                read = in.read(iv);
            } catch (IOException e) {
                String msg = "Unable to correctly read the Initialization Vector from the input stream.";
                throw new CryptoException(msg, e);
            }

            if (read != ivByteSize) {
                throw new CryptoException("Unable to read initialization vector bytes from the InputStream.  " +
                        "This is required when initialization vectors are autogenerated during an encryption " +
                        "operation.");
            }
        }

        decrypt(in, out, key, iv);
    }

    private void decrypt(InputStream in, OutputStream out, byte[] decryptionKey, byte[] iv) throws CryptoException {
        crypt(in, out, decryptionKey, iv, javax.crypto.Cipher.DECRYPT_MODE);
    }

    private void crypt(InputStream in, OutputStream out, byte[] keyBytes, byte[] iv, int cryptMode) throws CryptoException {
        if (in == null) {
            throw new NullPointerException("InputStream argument cannot be null.");
        }
        if (out == null) {
            throw new NullPointerException("OutputStream argument cannot be null.");
        }

        javax.crypto.Cipher cipher = initNewCipher(cryptMode, keyBytes, iv, true);

        CipherInputStream cis = new CipherInputStream(in, cipher);

        int bufSize = getStreamingBufferSize();
        byte[] buffer = new byte[bufSize];

        int bytesRead;
        try {
            while ((bytesRead = cis.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        } catch (IOException e) {
            throw new CryptoException(e);
        }
    }

    private javax.crypto.Cipher initNewCipher(int jcaCipherMode, byte[] key, byte[] iv, boolean streaming)
            throws CryptoException {

        javax.crypto.Cipher cipher = newCipherInstance(streaming);
        Key jdkKey = new SecretKeySpec(key, getAlgorithmName());
        IvParameterSpec ivSpec = null;
        if (iv != null && iv.length > 0) {
            ivSpec = new IvParameterSpec(iv);
        }

        init(cipher, jcaCipherMode, jdkKey, ivSpec, getSecureRandom());

        return cipher;
    }
}
