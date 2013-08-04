
package com.hwlcn.ldap.util.ssl;



import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedHashSet;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;

import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class WrapperKeyManager
       extends X509ExtendedKeyManager
{
  private final String certificateAlias;

  private final X509KeyManager[] keyManagers;


  protected WrapperKeyManager(final KeyManager[] keyManagers,
                              final String certificateAlias)
  {
    this.certificateAlias = certificateAlias;

    this.keyManagers = new X509KeyManager[keyManagers.length];
    for (int i=0; i < keyManagers.length; i++)
    {
      this.keyManagers[i] = (X509KeyManager) keyManagers[i];
    }
  }


  protected WrapperKeyManager(final X509KeyManager[] keyManagers,
                              final String certificateAlias)
  {
    this.keyManagers      = keyManagers;
    this.certificateAlias = certificateAlias;
  }



  public String getCertificateAlias()
  {
    return certificateAlias;
  }


  public final synchronized String[] getClientAliases(final String keyType,
                                          final Principal[] issuers)
  {
    final LinkedHashSet<String> clientAliases = new LinkedHashSet<String>();

    for (final X509KeyManager m : keyManagers)
    {
      final String[] aliases = m.getClientAliases(keyType, issuers);
      if (aliases != null)
      {
        clientAliases.addAll(Arrays.asList(aliases));
      }
    }

    if (clientAliases.isEmpty())
    {
      return null;
    }
    else
    {
      final String[] aliases = new String[clientAliases.size()];
      return clientAliases.toArray(aliases);
    }
  }


  public final synchronized String chooseClientAlias(final String[] keyType,
                                        final Principal[] issuers,
                                        final Socket socket)
  {
    if (certificateAlias == null)
    {
      for (final X509KeyManager m : keyManagers)
      {
        final String alias = m.chooseClientAlias(keyType, issuers, socket);
        if (alias != null)
        {
          return alias;
        }
      }

      return null;
    }
    else
    {
      for (final String s : keyType)
      {
        for (final X509KeyManager m : keyManagers)
        {
          final String[] aliases = m.getClientAliases(s, issuers);
          if (aliases != null)
          {
            for (final String alias : aliases)
            {
              if (alias.equals(certificateAlias))
              {
                return certificateAlias;
              }
            }
          }
        }
      }

      return null;
    }
  }


  @Override()
  public final synchronized String chooseEngineClientAlias(
                                        final String[] keyType,
                                        final Principal[] issuers,
                                        final SSLEngine engine)
  {
    if (certificateAlias == null)
    {
      for (final X509KeyManager m : keyManagers)
      {
        if (m instanceof X509ExtendedKeyManager)
        {
          final X509ExtendedKeyManager em = (X509ExtendedKeyManager) m;
          final String alias =
               em.chooseEngineClientAlias(keyType, issuers, engine);
          if (alias != null)
          {
            return alias;
          }
        }
        else
        {
          final String alias = m.chooseClientAlias(keyType, issuers, null);
          if (alias != null)
          {
            return alias;
          }
        }
      }

      return null;
    }
    else
    {
      for (final String s : keyType)
      {
        for (final X509KeyManager m : keyManagers)
        {
          final String[] aliases = m.getClientAliases(s, issuers);
          if (aliases != null)
          {
            for (final String alias : aliases)
            {
              if (alias.equals(certificateAlias))
              {
                return certificateAlias;
              }
            }
          }
        }
      }

      return null;
    }
  }


  public final synchronized String[] getServerAliases(final String keyType,
                                          final Principal[] issuers)
  {
    final LinkedHashSet<String> serverAliases = new LinkedHashSet<String>();

    for (final X509KeyManager m : keyManagers)
    {
      final String[] aliases = m.getServerAliases(keyType, issuers);
      if (aliases != null)
      {
        serverAliases.addAll(Arrays.asList(aliases));
      }
    }

    if (serverAliases.isEmpty())
    {
      return null;
    }
    else
    {
      final String[] aliases = new String[serverAliases.size()];
      return serverAliases.toArray(aliases);
    }
  }



  public final synchronized String chooseServerAlias(final String keyType,
                                        final Principal[] issuers,
                                        final Socket socket)
  {
    if (certificateAlias == null)
    {
      for (final X509KeyManager m : keyManagers)
      {
        final String alias = m.chooseServerAlias(keyType, issuers, socket);
        if (alias != null)
        {
          return alias;
        }
      }

      return null;
    }
    else
    {
      for (final X509KeyManager m : keyManagers)
      {
        final String[] aliases = m.getServerAliases(keyType, issuers);
        if (aliases != null)
        {
          for (final String alias : aliases)
          {
            if (alias.equals(certificateAlias))
            {
              return certificateAlias;
            }
          }
        }
      }

      return null;
    }
  }



  @Override()
  public final synchronized String chooseEngineServerAlias(final String keyType,
                                        final Principal[] issuers,
                                        final SSLEngine engine)
  {
    if (certificateAlias == null)
    {
      for (final X509KeyManager m : keyManagers)
      {
        if (m instanceof X509ExtendedKeyManager)
        {
          final X509ExtendedKeyManager em = (X509ExtendedKeyManager) m;
          final String alias =
               em.chooseEngineServerAlias(keyType, issuers, engine);
          if (alias != null)
          {
            return alias;
          }
        }
        else
        {
          final String alias = m.chooseServerAlias(keyType, issuers, null);
          if (alias != null)
          {
            return alias;
          }
        }
      }

      return null;
    }
    else
    {
      for (final X509KeyManager m : keyManagers)
      {
        final String[] aliases = m.getServerAliases(keyType, issuers);
        if (aliases != null)
        {
          for (final String alias : aliases)
          {
            if (alias.equals(certificateAlias))
            {
              return certificateAlias;
            }
          }
        }
      }

      return null;
    }
  }



  public final synchronized X509Certificate[] getCertificateChain(
                                                   final String alias)
  {
    for (final X509KeyManager m : keyManagers)
    {
      final X509Certificate[] chain = m.getCertificateChain(alias);
      if (chain != null)
      {
        return chain;
      }
    }

    return null;
  }



  public final synchronized PrivateKey getPrivateKey(final String alias)
  {
    for (final X509KeyManager m : keyManagers)
    {
      final PrivateKey key = m.getPrivateKey(alias);
      if (key != null)
      {
        return key;
      }
    }

    return null;
  }
}
