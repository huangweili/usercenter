package com.hwlcn.security.authc.credential;

import com.hwlcn.security.authc.AuthenticationInfo;
import com.hwlcn.security.authc.AuthenticationToken;
import com.hwlcn.security.codec.CodecSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;



public class SimpleCredentialsMatcher extends CodecSupport implements CredentialsMatcher {

    private static final Logger log = LoggerFactory.getLogger(SimpleCredentialsMatcher.class);

    protected Object getCredentials(AuthenticationToken token) {
        return token.getCredentials();
    }

    protected Object getCredentials(AuthenticationInfo info) {
        return info.getCredentials();
    }

    protected boolean equals(Object tokenCredentials, Object accountCredentials) {
        if (log.isDebugEnabled()) {
            log.debug("Performing credentials equality check for tokenCredentials of type [" +
                    tokenCredentials.getClass().getName() + " and accountCredentials of type [" +
                    accountCredentials.getClass().getName() + "]");
        }
        if (isByteSource(tokenCredentials) && isByteSource(accountCredentials)) {
            if (log.isDebugEnabled()) {
                log.debug("Both credentials arguments can be easily converted to byte arrays.  Performing " +
                        "array equals comparison");
            }
            byte[] tokenBytes = toBytes(tokenCredentials);
            byte[] accountBytes = toBytes(accountCredentials);
            return Arrays.equals(tokenBytes, accountBytes);
        } else {
            return accountCredentials.equals(tokenCredentials);
        }
    }

    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        Object tokenCredentials = getCredentials(token);
        Object accountCredentials = getCredentials(info);
        return equals(tokenCredentials, accountCredentials);
    }

}
