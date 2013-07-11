package com.hwlcn.security.authc.credential;

import com.hwlcn.security.crypto.hash.Hash;


public interface HashingPasswordService extends PasswordService {

    Hash hashPassword(Object plaintext) throws IllegalArgumentException;

    boolean passwordsMatch(Object plaintext, Hash savedPasswordHash);
}
