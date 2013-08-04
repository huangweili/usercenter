
package com.hwlcn.ldap.util.ssl;



import java.io.File;
import java.io.FileInputStream;
import java.io.Serializable;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.Validator.*;
import static com.hwlcn.ldap.util.ssl.SSLMessages.*;




@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TrustStoreTrustManager
       implements X509TrustManager, Serializable
{

  private static final long serialVersionUID = -4093869102727719415L;

  private final boolean examineValidityDates;

  private final char[] trustStorePIN;

  private final String trustStoreFile;

  private final String trustStoreFormat;

  public TrustStoreTrustManager(final File trustStoreFile)
  {
    this(trustStoreFile.getAbsolutePath(), null, null, true);
  }

  public TrustStoreTrustManager(final String trustStoreFile)
  {
    this(trustStoreFile, null, null, true);
  }

  public TrustStoreTrustManager(final File trustStoreFile,
                                final char[] trustStorePIN,
                                final String trustStoreFormat,
                                final boolean examineValidityDates)
  {
    this(trustStoreFile.getAbsolutePath(), trustStorePIN, trustStoreFormat,
         examineValidityDates);
  }


  public TrustStoreTrustManager(final String trustStoreFile,
                                final char[] trustStorePIN,
                                final String trustStoreFormat,
                                final boolean examineValidityDates)
  {
    ensureNotNull(trustStoreFile);

    this.trustStoreFile       = trustStoreFile;
    this.trustStorePIN        = trustStorePIN;
    this.examineValidityDates = examineValidityDates;

    if (trustStoreFormat == null)
    {
      this.trustStoreFormat = KeyStore.getDefaultType();
    }
    else
    {
      this.trustStoreFormat = trustStoreFormat;
    }
  }

  public String getTrustStoreFile()
  {
    return trustStoreFile;
  }

  public String getTrustStoreFormat()
  {
    return trustStoreFormat;
  }

  public boolean examineValidityDates()
  {
    return examineValidityDates;
  }

  private synchronized X509TrustManager[] getTrustManagers(
                                               final X509Certificate[] chain)
          throws CertificateException
  {
    if (examineValidityDates)
    {
      final Date d = new Date();
      for (final X509Certificate c : chain)
      {
        c.checkValidity(d);
      }
    }

    final File f = new File(trustStoreFile);
    if (! f.exists())
    {
      throw new CertificateException(
           ERR_TRUSTSTORE_NO_SUCH_FILE.get(trustStoreFile));
    }

    final KeyStore ks;
    try
    {
      ks = KeyStore.getInstance(trustStoreFormat);
    }
    catch (Exception e)
    {
      debugException(e);

      throw new CertificateException(
           ERR_TRUSTSTORE_UNSUPPORTED_FORMAT.get(trustStoreFormat), e);
    }

    FileInputStream inputStream = null;
    try
    {
      inputStream = new FileInputStream(f);
      ks.load(inputStream, trustStorePIN);
    }
    catch (Exception e)
    {
      debugException(e);

      throw new CertificateException(
           ERR_TRUSTSTORE_CANNOT_LOAD.get(trustStoreFile, trustStoreFormat,
                                          String.valueOf(e)),
           e);
    }
    finally
    {
      if (inputStream != null)
      {
        try
        {
          inputStream.close();
        }
        catch (Exception e)
        {
          debugException(e);
        }
      }
    }

    try
    {
      final TrustManagerFactory factory = TrustManagerFactory.getInstance(
           TrustManagerFactory.getDefaultAlgorithm());
      factory.init(ks);
      final TrustManager[] trustManagers = factory.getTrustManagers();
      final X509TrustManager[] x509TrustManagers =
           new X509TrustManager[trustManagers.length];
      for (int i=0; i < trustManagers.length; i++)
      {
        x509TrustManagers[i] = (X509TrustManager) trustManagers[i];
      }
      return x509TrustManagers;
    }
    catch (Exception e)
    {
      debugException(e);

      throw new CertificateException(
           ERR_TRUSTSTORE_CANNOT_GET_TRUST_MANAGERS.get(trustStoreFile,
                trustStoreFormat, String.valueOf(e)),
           e);
    }
  }


  public synchronized void checkClientTrusted(final X509Certificate[] chain,
                                final String authType)
         throws CertificateException
  {
    for (final X509TrustManager m : getTrustManagers(chain))
    {
      m.checkClientTrusted(chain, authType);
    }
  }


  public synchronized void checkServerTrusted(final X509Certificate[] chain,
                                final String authType)
         throws CertificateException
  {
    for (final X509TrustManager m : getTrustManagers(chain))
    {
      m.checkServerTrusted(chain, authType);
    }
  }

  public synchronized X509Certificate[] getAcceptedIssuers()
  {
    return new X509Certificate[0];
  }
}
