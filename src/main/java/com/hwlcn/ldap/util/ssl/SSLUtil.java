package com.hwlcn.ldap.util.ssl;



import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;

import com.hwlcn.ldap.util.Debug;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides a simple interface for creating {@code SSLContext} and
 * {@code SSLSocketFactory} instances, which may be used to create SSL-based
 * connections, or secure existing connections with StartTLS.
 * <BR><BR>
 * <H2>Example 1</H2>
 * The following example demonstrates the use of the SSL helper to create an
 * SSL-based LDAP connection that will blindly trust any certificate that the
 * server presents:
 * <PRE>
 *   SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
 *
 *   LDAPConnection connection =
 *        new LDAPConnection(sslUtil.createSSLSocketFactory());
 *   connection.connect("server.example.com", 636);
 * </PRE>
 * <BR>
 * <H2>Example 2</H2>
 * The following example demonstrates the use of the SSL helper to create a
 * non-secure LDAP connection and then use the StartTLS extended operation to
 * secure it.  It will use a trust store to determine whether to trust the
 * server certificate.
 * <PRE>
 *   LDAPConnection connection = new LDAPConnection();
 *   connection.connect("server.example.com", 389);
 *
 *   String trustStoreFile  = "/path/to/trust/store/file";
 *   SSLUtil sslUtil = new SSLUtil(new TrustStoreTrustManager(trustStoreFile));
 *
 *   ExtendedResult extendedResult = connection.processExtendedOperation(
 *        new StartTLSExtendedRequest(sslUtil.createSSLContext()));
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SSLUtil
{

  private static final AtomicReference<String> DEFAULT_SSL_PROTOCOL =
       new AtomicReference<String>("TLSv1");

  static
  {

    try
    {
      final Method getDefaultMethod =
           SSLContext.class.getMethod("getDefault");
      final SSLContext defaultContext =
           (SSLContext) getDefaultMethod.invoke(null);

      final Method getSupportedParamsMethod =
           SSLContext.class.getMethod("getSupportedSSLParameters");
      final Object paramsObj = getSupportedParamsMethod.invoke(defaultContext);

      final Class<?> sslParamsClass =
           Class.forName("javax.net.ssl.SSLParameters");
      final Method getProtocolsMethod =
           sslParamsClass.getMethod("getProtocols");
      final String[] supportedProtocols =
           (String[]) getProtocolsMethod.invoke(paramsObj);

      final HashSet<String> protocolMap =
           new HashSet<String>(Arrays.asList(supportedProtocols));
      if (protocolMap.contains("TLSv1.2"))
      {
        DEFAULT_SSL_PROTOCOL.set("TLSv1.2");
      }
      else if (protocolMap.contains("TLSv1.1"))
      {
        DEFAULT_SSL_PROTOCOL.set("TLSv1.1");
      }
      else if (protocolMap.contains("TLSv1"))
      {
        DEFAULT_SSL_PROTOCOL.set("TLSv1");
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }
  }



  private final KeyManager[] keyManagers;

  private final TrustManager[] trustManagers;


  public SSLUtil()
  {
    keyManagers   = null;
    trustManagers = null;
  }



  public SSLUtil(final TrustManager trustManager)
  {
    keyManagers = null;

    if (trustManager == null)
    {
      trustManagers = null;
    }
    else
    {
      trustManagers = new TrustManager[] { trustManager };
    }
  }




  public SSLUtil(final TrustManager[] trustManagers)
  {
    keyManagers = null;

    if ((trustManagers == null) || (trustManagers.length == 0))
    {
      this.trustManagers = null;
    }
    else
    {
      this.trustManagers = trustManagers;
    }
  }



  public SSLUtil(final KeyManager keyManager, final TrustManager trustManager)
  {
    if (keyManager == null)
    {
      keyManagers = null;
    }
    else
    {
      keyManagers = new KeyManager[] { keyManager };
    }

    if (trustManager == null)
    {
      trustManagers = null;
    }
    else
    {
      trustManagers = new TrustManager[] { trustManager };
    }
  }




  public SSLUtil(final KeyManager[] keyManagers,
                 final TrustManager[] trustManagers)
  {
    if ((keyManagers == null) || (keyManagers.length == 0))
    {
      this.keyManagers = null;
    }
    else
    {
      this.keyManagers = keyManagers;
    }

    if ((trustManagers == null) || (trustManagers.length == 0))
    {
      this.trustManagers = null;
    }
    else
    {
      this.trustManagers = trustManagers;
    }
  }



  public KeyManager[] getKeyManagers()
  {
    return keyManagers;
  }




  public TrustManager[] getTrustManagers()
  {
    return trustManagers;
  }




  public SSLContext createSSLContext()
         throws GeneralSecurityException
  {
    return createSSLContext(DEFAULT_SSL_PROTOCOL.get());
  }



  public SSLContext createSSLContext(final String protocol)
         throws GeneralSecurityException
  {
    ensureNotNull(protocol);

    final SSLContext sslContext = SSLContext.getInstance(protocol);
    sslContext.init(keyManagers, trustManagers, null);
    return sslContext;
  }




  public SSLContext createSSLContext(final String protocol,
                                     final String provider)
         throws GeneralSecurityException
  {
    ensureNotNull(protocol, provider);

    final SSLContext sslContext = SSLContext.getInstance(protocol, provider);
    sslContext.init(keyManagers, trustManagers, null);
    return sslContext;
  }



  public SSLSocketFactory createSSLSocketFactory()
         throws GeneralSecurityException
  {
    return createSSLContext().getSocketFactory();
  }




  public SSLSocketFactory createSSLSocketFactory(final String protocol)
         throws GeneralSecurityException
  {
    return createSSLContext(protocol).getSocketFactory();
  }



  public SSLSocketFactory createSSLSocketFactory(final String protocol,
                                                 final String provider)
         throws GeneralSecurityException
  {
    return createSSLContext(protocol, provider).getSocketFactory();
  }




  public SSLServerSocketFactory createSSLServerSocketFactory()
         throws GeneralSecurityException
  {
    return createSSLContext().getServerSocketFactory();
  }




  public SSLServerSocketFactory createSSLServerSocketFactory(
                                     final String protocol)
         throws GeneralSecurityException
  {
    return createSSLContext(protocol).getServerSocketFactory();
  }


  public SSLServerSocketFactory createSSLServerSocketFactory(
                                     final String protocol,
                                     final String provider)
         throws GeneralSecurityException
  {
    return createSSLContext(protocol, provider).getServerSocketFactory();
  }



  public static String getDefaultSSLProtocol()
  {
    return DEFAULT_SSL_PROTOCOL.get();
  }


  public static void setDefaultSSLProtocol(final String defaultSSLProtocol)
  {
    ensureNotNull(defaultSSLProtocol);

    DEFAULT_SSL_PROTOCOL.set(defaultSSLProtocol);
  }
}
