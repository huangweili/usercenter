package com.hwlcn.security.authc.credential;

import com.hwlcn.security.authc.AuthenticationInfo;
import com.hwlcn.security.authc.AuthenticationToken;
import com.hwlcn.security.authc.SaltedAuthenticationInfo;
import com.hwlcn.security.codec.Base64;
import com.hwlcn.security.codec.CodecSupport;
import com.hwlcn.security.codec.Hex;
import com.hwlcn.security.crypto.hash.Hash;
import com.hwlcn.security.crypto.hash.SimpleHash;
import com.hwlcn.security.util.StringUtils;


public class HashedCredentialsMatcher extends SimpleCredentialsMatcher {

    private String hashAlgorithm;
    private int hashIterations;
    private boolean hashSalted;
    private boolean storedCredentialsHexEncoded;

    public HashedCredentialsMatcher() {
        this.hashAlgorithm = null;
        this.hashSalted = false;
        this.hashIterations = 1;
        this.storedCredentialsHexEncoded = true; //false means Base64-encoded
    }

    public HashedCredentialsMatcher(String hashAlgorithmName) {
        this();
        if (!StringUtils.hasText(hashAlgorithmName)) {
            throw new IllegalArgumentException("hashAlgorithmName cannot be null or empty.");
        }
        this.hashAlgorithm = hashAlgorithmName;
    }

    public String getHashAlgorithmName() {
        return hashAlgorithm;
    }

    public void setHashAlgorithmName(String hashAlgorithmName) {
        this.hashAlgorithm = hashAlgorithmName;
    }

    public boolean isStoredCredentialsHexEncoded() {
        return storedCredentialsHexEncoded;
    }

    public void setStoredCredentialsHexEncoded(boolean storedCredentialsHexEncoded) {
        this.storedCredentialsHexEncoded = storedCredentialsHexEncoded;
    }


    public int getHashIterations() {
        return hashIterations;
    }

    public void setHashIterations(int hashIterations) {
        if (hashIterations < 1) {
            this.hashIterations = 1;
        } else {
            this.hashIterations = hashIterations;
        }
    }


    protected Object getCredentials(AuthenticationInfo info) {
        Object credentials = info.getCredentials();

        byte[] storedBytes = toBytes(credentials);

        if (credentials instanceof String || credentials instanceof char[]) {
            if (isStoredCredentialsHexEncoded()) {
                storedBytes = Hex.decode(storedBytes);
            } else {
                storedBytes = Base64.decode(storedBytes);
            }
        }
        SimpleHash hash = newHashInstance();
        hash.setBytes(storedBytes);
        return hash;
    }


    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        Object tokenHashedCredentials = hashProvidedCredentials(token, info);
        Object accountCredentials = getCredentials(info);
        return equals(tokenHashedCredentials, accountCredentials);
    }


    protected Object hashProvidedCredentials(AuthenticationToken token, AuthenticationInfo info) {
        Object salt = null;
        if (info instanceof SaltedAuthenticationInfo) {
            salt = ((SaltedAuthenticationInfo) info).getCredentialsSalt();
        }
        return hashProvidedCredentials(token.getCredentials(), salt, getHashIterations());
    }

    private String assertHashAlgorithmName() throws IllegalStateException {
        String hashAlgorithmName = getHashAlgorithmName();
        if (hashAlgorithmName == null) {
            String msg = "Required 'hashAlgorithmName' property has not been set.  This is required to execute " +
                    "the hashing algorithm.";
            throw new IllegalStateException(msg);
        }
        return hashAlgorithmName;
    }

    protected Hash hashProvidedCredentials(Object credentials, Object salt, int hashIterations) {
        String hashAlgorithmName = assertHashAlgorithmName();
        return new SimpleHash(hashAlgorithmName, credentials, salt, hashIterations);
    }


    protected SimpleHash newHashInstance() {
        String hashAlgorithmName = assertHashAlgorithmName();
        return new SimpleHash(hashAlgorithmName);
    }

}
