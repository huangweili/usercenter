package com.hwlcn.security.authc.credential;

import com.hwlcn.security.authc.AuthenticationInfo;
import com.hwlcn.security.authc.AuthenticationToken;
import com.hwlcn.security.crypto.hash.Hash;


public class PasswordMatcher implements CredentialsMatcher {

    private PasswordService passwordService;

    public PasswordMatcher() {
        this.passwordService = new DefaultPasswordService();
    }

    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {

        PasswordService service = ensurePasswordService();

        Object submittedPassword = getSubmittedPassword(token);
        Object storedCredentials = getStoredPassword(info);
        assertStoredCredentialsType(storedCredentials);

        if (storedCredentials instanceof Hash) {
            Hash hashedPassword = (Hash)storedCredentials;
            HashingPasswordService hashingService = assertHashingPasswordService(service);
            return hashingService.passwordsMatch(submittedPassword, hashedPassword);
        }
        String formatted = (String)storedCredentials;
        return passwordService.passwordsMatch(submittedPassword, formatted);
    }

    private HashingPasswordService assertHashingPasswordService(PasswordService service) {
        if (service instanceof HashingPasswordService) {
            return (HashingPasswordService) service;
        }
        String msg = "AuthenticationInfo's stored credentials are a Hash instance, but the " +
                "configured passwordService is not a " +
                HashingPasswordService.class.getName() + " instance.  This is required to perform Hash " +
                "object password comparisons.";
        throw new IllegalStateException(msg);
    }

    private PasswordService ensurePasswordService() {
        PasswordService service = getPasswordService();
        if (service == null) {
            String msg = "Required PasswordService has not been configured.";
            throw new IllegalStateException(msg);
        }
        return service;
    }

    protected Object getSubmittedPassword(AuthenticationToken token) {
        return token != null ? token.getCredentials() : null;
    }

    private void assertStoredCredentialsType(Object credentials) {
        if (credentials instanceof String || credentials instanceof Hash) {
            return;
        }

        String msg = "Stored account credentials are expected to be either a " +
                Hash.class.getName() + " instance or a formatted hash String.";
        throw new IllegalArgumentException(msg);
    }

    protected Object getStoredPassword(AuthenticationInfo storedAccountInfo) {
        Object stored = storedAccountInfo != null ? storedAccountInfo.getCredentials() : null;
        if (stored instanceof char[]) {
            stored = new String((char[])stored);
        }
        return stored;
    }

    public PasswordService getPasswordService() {
        return passwordService;
    }

    public void setPasswordService(PasswordService passwordService) {
        this.passwordService = passwordService;
    }
}
