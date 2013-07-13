
package com.hwlcn.security.crypto.hash;

import com.hwlcn.security.util.ByteSource;
import com.hwlcn.security.crypto.RandomNumberGenerator;
import com.hwlcn.security.crypto.SecureRandomNumberGenerator;
public class DefaultHashService implements ConfigurableHashService {

   private RandomNumberGenerator rng;

   private String algorithmName;

  private ByteSource privateSalt;


    private int iterations;


    private boolean generatePublicSalt;


    public DefaultHashService() {
        this.algorithmName = "SHA-512";
        this.iterations = 1;
        this.generatePublicSalt = false;
        this.rng = new SecureRandomNumberGenerator();
    }


    public Hash computeHash(HashRequest request) {
        if (request == null || request.getSource() == null || request.getSource().isEmpty()) {
            return null;
        }

        String algorithmName = getAlgorithmName(request);
        ByteSource source = request.getSource();
        int iterations = getIterations(request);

        ByteSource publicSalt = getPublicSalt(request);
        ByteSource privateSalt = getPrivateSalt();
        ByteSource salt = combine(privateSalt, publicSalt);

        Hash computed = new SimpleHash(algorithmName, source, salt, iterations);

        SimpleHash result = new SimpleHash(algorithmName);
        result.setBytes(computed.getBytes());
        result.setIterations(iterations);
        result.setSalt(publicSalt);

        return result;
    }

    protected String getAlgorithmName(HashRequest request) {
        String name = request.getAlgorithmName();
        if (name == null) {
            name = getHashAlgorithmName();
        }
        return name;
    }

    protected int getIterations(HashRequest request) {
        int iterations = Math.max(0, request.getIterations());
        if (iterations < 1) {
            iterations = Math.max(1, getHashIterations());
        }
        return iterations;
    }

    protected ByteSource getPublicSalt(HashRequest request) {

        ByteSource publicSalt = request.getSalt();

        if (publicSalt != null && !publicSalt.isEmpty()) {
            return publicSalt;
        }

        publicSalt = null;

        ByteSource privateSalt = getPrivateSalt();
        boolean privateSaltExists = privateSalt != null && !privateSalt.isEmpty();

        if (privateSaltExists || isGeneratePublicSalt()) {
            publicSalt = getRandomNumberGenerator().nextBytes();
        }

        return publicSalt;
    }

    protected ByteSource combine(ByteSource privateSalt, ByteSource publicSalt) {

        byte[] privateSaltBytes = privateSalt != null ? privateSalt.getBytes() : null;
        int privateSaltLength = privateSaltBytes != null ? privateSaltBytes.length : 0;

        byte[] publicSaltBytes = publicSalt != null ? publicSalt.getBytes() : null;
        int extraBytesLength = publicSaltBytes != null ? publicSaltBytes.length : 0;

        int length = privateSaltLength + extraBytesLength;

        if (length <= 0) {
            return null;
        }

        byte[] combined = new byte[length];

        int i = 0;
        for (int j = 0; j < privateSaltLength; j++) {
            assert privateSaltBytes != null;
            combined[i++] = privateSaltBytes[j];
        }
        for (int j = 0; j < extraBytesLength; j++) {
            assert publicSaltBytes != null;
            combined[i++] = publicSaltBytes[j];
        }

        return ByteSource.Util.bytes(combined);
    }

    public void setHashAlgorithmName(String name) {
        this.algorithmName = name;
    }

    public String getHashAlgorithmName() {
        return this.algorithmName;
    }

    public void setPrivateSalt(ByteSource privateSalt) {
        this.privateSalt = privateSalt;
    }

    public ByteSource getPrivateSalt() {
        return this.privateSalt;
    }

    public void setHashIterations(int count) {
        this.iterations = count;
    }

    public int getHashIterations() {
        return this.iterations;
    }

    public void setRandomNumberGenerator(RandomNumberGenerator rng) {
        this.rng = rng;
    }

    public RandomNumberGenerator getRandomNumberGenerator() {
        return this.rng;
    }

    public boolean isGeneratePublicSalt() {
        return generatePublicSalt;
    }

    public void setGeneratePublicSalt(boolean generatePublicSalt) {
        this.generatePublicSalt = generatePublicSalt;
    }
}
