
package com.hwlcn.ldap.util.ssl;



import java.security.KeyStoreException;
import java.security.KeyStore;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;

import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.ssl.SSLMessages.*;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PKCS11KeyManager
       extends WrapperKeyManager
{

  private static final String PKCS11_KEY_STORE_TYPE = "PKCS11";




  public PKCS11KeyManager(final char[] keyStorePIN,
                          final String certificateAlias)
         throws KeyStoreException
  {
    super(getKeyManagers(keyStorePIN), certificateAlias);
  }



  private static KeyManager[] getKeyManagers(final char[] keyStorePIN)
          throws KeyStoreException
  {
    final KeyStore ks = KeyStore.getInstance(PKCS11_KEY_STORE_TYPE);
    try
    {
      ks.load(null, keyStorePIN);
    }
    catch (Exception e)
    {
      debugException(e);

      throw new KeyStoreException(
           ERR_PKCS11_CANNOT_ACCESS.get(String.valueOf(e)), e);
    }

    try
    {
      final KeyManagerFactory factory = KeyManagerFactory.getInstance(
           KeyManagerFactory.getDefaultAlgorithm());
      factory.init(ks, keyStorePIN);
      return factory.getKeyManagers();
    }
    catch (Exception e)
    {
      debugException(e);

      throw new KeyStoreException(
           ERR_PKCS11_CANNOT_GET_KEY_MANAGERS.get(String.valueOf(e)), e);
    }
  }
}
