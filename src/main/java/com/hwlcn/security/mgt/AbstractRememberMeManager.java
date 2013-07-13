package com.hwlcn.security.mgt;

import com.hwlcn.security.authc.AuthenticationException;
import com.hwlcn.security.authc.AuthenticationInfo;
import com.hwlcn.security.authc.AuthenticationToken;
import com.hwlcn.security.authc.RememberMeAuthenticationToken;
import com.hwlcn.security.codec.Base64;
import com.hwlcn.security.crypto.AesCipherService;
import com.hwlcn.security.crypto.CipherService;
import com.hwlcn.security.io.DefaultSerializer;
import com.hwlcn.security.io.Serializer;
import com.hwlcn.security.subject.PrincipalCollection;
import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.subject.SubjectContext;
import com.hwlcn.security.util.ByteSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public abstract class AbstractRememberMeManager implements RememberMeManager {

    private static final Logger log = LoggerFactory.getLogger(AbstractRememberMeManager.class);

    private static final byte[] DEFAULT_CIPHER_KEY_BYTES = Base64.decode("kPH+bIxk5D2deZiIxcaaaA==");

    private Serializer<PrincipalCollection> serializer;

    private CipherService cipherService;


    private byte[] encryptionCipherKey;


    private byte[] decryptionCipherKey;


    public AbstractRememberMeManager() {
        this.serializer = new DefaultSerializer<PrincipalCollection>();
        this.cipherService = new AesCipherService();
        setCipherKey(DEFAULT_CIPHER_KEY_BYTES);
    }

    public Serializer<PrincipalCollection> getSerializer() {
        return serializer;
    }

    public void setSerializer(Serializer<PrincipalCollection> serializer) {
        this.serializer = serializer;
    }

    public CipherService getCipherService() {
        return cipherService;
    }

    public void setCipherService(CipherService cipherService) {
        this.cipherService = cipherService;
    }

    public byte[] getEncryptionCipherKey() {
        return encryptionCipherKey;
    }

    public void setEncryptionCipherKey(byte[] encryptionCipherKey) {
        this.encryptionCipherKey = encryptionCipherKey;
    }

    public byte[] getDecryptionCipherKey() {
        return decryptionCipherKey;
    }

    public void setDecryptionCipherKey(byte[] decryptionCipherKey) {
        this.decryptionCipherKey = decryptionCipherKey;
    }

    public byte[] getCipherKey() {
        return getEncryptionCipherKey();
    }

    public void setCipherKey(byte[] cipherKey) {
        setEncryptionCipherKey(cipherKey);
        setDecryptionCipherKey(cipherKey);
    }

    protected abstract void forgetIdentity(Subject subject);

    protected boolean isRememberMe(AuthenticationToken token) {
        return token != null && (token instanceof RememberMeAuthenticationToken) &&
                ((RememberMeAuthenticationToken) token).isRememberMe();
    }

    public void onSuccessfulLogin(Subject subject, AuthenticationToken token, AuthenticationInfo info) {
        forgetIdentity(subject);

        if (isRememberMe(token)) {
            rememberIdentity(subject, token, info);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("AuthenticationToken did not indicate RememberMe is requested.  " +
                        "RememberMe functionality will not be executed for corresponding account.");
            }
        }
    }

    public void rememberIdentity(Subject subject, AuthenticationToken token, AuthenticationInfo authcInfo) {
        PrincipalCollection principals = getIdentityToRemember(subject, authcInfo);
        rememberIdentity(subject, principals);
    }

    protected PrincipalCollection getIdentityToRemember(Subject subject, AuthenticationInfo info) {
        return info.getPrincipals();
    }

    protected void rememberIdentity(Subject subject, PrincipalCollection accountPrincipals) {
        byte[] bytes = convertPrincipalsToBytes(accountPrincipals);
        rememberSerializedIdentity(subject, bytes);
    }

    protected byte[] convertPrincipalsToBytes(PrincipalCollection principals) {
        byte[] bytes = serialize(principals);
        if (getCipherService() != null) {
            bytes = encrypt(bytes);
        }
        return bytes;
    }

    protected abstract void rememberSerializedIdentity(Subject subject, byte[] serialized);

    public PrincipalCollection getRememberedPrincipals(SubjectContext subjectContext) {
        PrincipalCollection principals = null;
        try {
            byte[] bytes = getRememberedSerializedIdentity(subjectContext);
            if (bytes != null && bytes.length > 0) {
                principals = convertBytesToPrincipals(bytes, subjectContext);
            }
        } catch (RuntimeException re) {
            principals = onRememberedPrincipalFailure(re, subjectContext);
        }

        return principals;
    }

    protected abstract byte[] getRememberedSerializedIdentity(SubjectContext subjectContext);

    protected PrincipalCollection convertBytesToPrincipals(byte[] bytes, SubjectContext subjectContext) {
        if (getCipherService() != null) {
            bytes = decrypt(bytes);
        }
        return deserialize(bytes);
    }

    protected PrincipalCollection onRememberedPrincipalFailure(RuntimeException e, SubjectContext context) {
        if (log.isDebugEnabled()) {
            log.debug("There was a failure while trying to retrieve remembered principals.  This could be due to a " +
                    "configuration problem or corrupted principals.  This could also be due to a recently " +
                    "changed encryption key.  The remembered identity will be forgotten and not used for this " +
                    "request.", e);
        }
        forgetIdentity(context);
        throw e;
    }

    protected byte[] encrypt(byte[] serialized) {
        byte[] value = serialized;
        CipherService cipherService = getCipherService();
        if (cipherService != null) {
            ByteSource byteSource = cipherService.encrypt(serialized, getEncryptionCipherKey());
            value = byteSource.getBytes();
        }
        return value;
    }

    protected byte[] decrypt(byte[] encrypted) {
        byte[] serialized = encrypted;
        CipherService cipherService = getCipherService();
        if (cipherService != null) {
            ByteSource byteSource = cipherService.decrypt(encrypted, getDecryptionCipherKey());
            serialized = byteSource.getBytes();
        }
        return serialized;
    }

    protected byte[] serialize(PrincipalCollection principals) {
        return getSerializer().serialize(principals);
    }

    protected PrincipalCollection deserialize(byte[] serializedIdentity) {
        return getSerializer().deserialize(serializedIdentity);
    }

    public void onFailedLogin(Subject subject, AuthenticationToken token, AuthenticationException ae) {
        forgetIdentity(subject);
    }

    public void onLogout(Subject subject) {
        forgetIdentity(subject);
    }
}
