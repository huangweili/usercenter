package com.hwlcn.security.authc.credential;


public interface PasswordService {
    //密码加密
    String encryptPassword(Object plaintextPassword) throws IllegalArgumentException;

    //密码对比
    boolean passwordsMatch(Object submittedPlaintext, String encrypted);
}
