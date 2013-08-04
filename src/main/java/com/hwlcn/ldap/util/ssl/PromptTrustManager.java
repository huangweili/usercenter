
package com.hwlcn.ldap.util.ssl;


import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.PrintStream;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.ssl.SSLMessages.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PromptTrustManager
       implements X509TrustManager
{

  private static final MessageDigest MD5;

  private static final MessageDigest SHA1;



  static
  {
    MessageDigest d = null;
    try
    {
      d = MessageDigest.getInstance("MD5");
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new RuntimeException(e);
    }
    MD5 = d;

    d = null;
    try
    {
      d = MessageDigest.getInstance("SHA-1");
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new RuntimeException(e);
    }
    SHA1 = d;
  }


  private final boolean examineValidityDates;

  private final ConcurrentHashMap<String,Boolean> acceptedCerts;

  private final InputStream in;

  private final PrintStream out;

  private final String acceptedCertsFile;


  public PromptTrustManager()
  {
    this(null, true, null, null);
  }



  public PromptTrustManager(final String acceptedCertsFile)
  {
    this(acceptedCertsFile, true, null, null);
  }


  public PromptTrustManager(final String acceptedCertsFile,
                            final boolean examineValidityDates,
                            final InputStream in, final PrintStream out)
  {
    this.acceptedCertsFile    = acceptedCertsFile;
    this.examineValidityDates = examineValidityDates;

    if (in == null)
    {
      this.in = System.in;
    }
    else
    {
      this.in = in;
    }

    if (out == null)
    {
      this.out = System.out;
    }
    else
    {
      this.out = out;
    }

    acceptedCerts = new ConcurrentHashMap<String,Boolean>();

    if (acceptedCertsFile != null)
    {
      BufferedReader r = null;
      try
      {
        final File f = new File(acceptedCertsFile);
        if (f.exists())
        {
          r = new BufferedReader(new FileReader(f));
          while (true)
          {
            final String line = r.readLine();
            if (line == null)
            {
              break;
            }
            acceptedCerts.put(line, false);
          }
        }
      }
      catch (Exception e)
      {
        debugException(e);
      }
      finally
      {
        if (r != null)
        {
          try
          {
            r.close();
          }
          catch (Exception e)
          {
            debugException(e);
          }
        }
      }
    }
  }


  private void writeCacheFile()
          throws IOException
  {
    final File tempFile = new File(acceptedCertsFile + ".new");

    BufferedWriter w = null;
    try
    {
      w = new BufferedWriter(new FileWriter(tempFile));

      for (final String certBytes : acceptedCerts.keySet())
      {
        w.write(certBytes);
        w.newLine();
      }
    }
    finally
    {
      if (w != null)
      {
        w.close();
      }
    }

    final File cacheFile = new File(acceptedCertsFile);
    if (cacheFile.exists())
    {
      final File oldFile = new File(acceptedCertsFile + ".previous");
      if (oldFile.exists())
      {
        oldFile.delete();
      }

      cacheFile.renameTo(oldFile);
    }

    tempFile.renameTo(cacheFile);
  }

  private synchronized void checkCertificateChain(final X509Certificate[] chain,
                                                  final boolean serverCert)
          throws CertificateException
  {
    String validityWarning = null;
    final Date currentDate = new Date();
    final X509Certificate c = chain[0];
    if (examineValidityDates)
    {
      if (currentDate.before(c.getNotBefore()))
      {
        validityWarning = WARN_PROMPT_NOT_YET_VALID.get();
      }
      else if (currentDate.after(c.getNotAfter()))
      {
        validityWarning = WARN_PROMPT_EXPIRED.get();
      }
    }


    if ((! examineValidityDates) || (validityWarning == null))
    {
      final String certBytes = toLowerCase(toHex(c.getSignature()));
      final Boolean accepted = acceptedCerts.get(certBytes);
      if (accepted != null)
      {
        if ((validityWarning == null) || (! examineValidityDates) ||
            Boolean.TRUE.equals(accepted))
        {
          return;
        }
      }
    }


    if (serverCert)
    {
      out.println(INFO_PROMPT_SERVER_HEADING.get());
    }
    else
    {
      out.println(INFO_PROMPT_CLIENT_HEADING.get());
    }

    out.println('\t' + INFO_PROMPT_SUBJECT.get(
         c.getSubjectX500Principal().getName(X500Principal.CANONICAL)));
    out.println("\t\t" + INFO_PROMPT_MD5_FINGERPRINT.get(
         getFingerprint(c, MD5)));
    out.println("\t\t" + INFO_PROMPT_SHA1_FINGERPRINT.get(
         getFingerprint(c, SHA1)));

    for (int i=1; i < chain.length; i++)
    {
      out.println('\t' + INFO_PROMPT_ISSUER_SUBJECT.get(i,
           chain[i].getSubjectX500Principal().getName(
                X500Principal.CANONICAL)));
      out.println("\t\t" + INFO_PROMPT_MD5_FINGERPRINT.get(
           getFingerprint(chain[i], MD5)));
      out.println("\t\t" + INFO_PROMPT_SHA1_FINGERPRINT.get(
           getFingerprint(chain[i], SHA1)));
    }

    out.println(INFO_PROMPT_VALIDITY.get(String.valueOf(c.getNotBefore()),
         String.valueOf(c.getNotAfter())));

    if (chain.length == 1)
    {
      out.println();
      out.println(WARN_PROMPT_SELF_SIGNED.get());
    }

    if (validityWarning != null)
    {
      out.println();
      out.println(validityWarning);
    }

    final BufferedReader reader = new BufferedReader(new InputStreamReader(in));
    while (true)
    {
      try
      {
        out.println();
        out.println(INFO_PROMPT_MESSAGE.get());
        out.flush();
        final String line = reader.readLine();
        if (line.equalsIgnoreCase("y") || line.equalsIgnoreCase("yes"))
        {
          break;
        }
        else if (line.equalsIgnoreCase("n") || line.equalsIgnoreCase("no"))
        {
          throw new CertificateException(
               ERR_CERTIFICATE_REJECTED_BY_USER.get());
        }
      }
      catch (CertificateException ce)
      {
        throw ce;
      }
      catch (Exception e)
      {
        debugException(e);
      }
    }

    final String certBytes = toLowerCase(toHex(c.getSignature()));
    acceptedCerts.put(certBytes, (validityWarning != null));

    if (acceptedCertsFile != null)
    {
      try
      {
        writeCacheFile();
      }
      catch (Exception e)
      {
        debugException(e);
      }
    }
  }


  private static String getFingerprint(final X509Certificate c,
                                       final MessageDigest d)
          throws CertificateException
  {
    final byte[] encodedCertBytes = c.getEncoded();

    final byte[] digestBytes;
    synchronized (d)
    {
      digestBytes = d.digest(encodedCertBytes);
    }

    final StringBuilder buffer = new StringBuilder(3 * encodedCertBytes.length);
    toHex(digestBytes, ":", buffer);
    return buffer.toString();
  }



  public boolean examineValidityDates()
  {
    return examineValidityDates;
  }



  public void checkClientTrusted(final X509Certificate[] chain,
                                 final String authType)
         throws CertificateException
  {
    checkCertificateChain(chain, false);
  }

  public void checkServerTrusted(final X509Certificate[] chain,
                                 final String authType)
         throws CertificateException
  {
    checkCertificateChain(chain, true);
  }


  public X509Certificate[] getAcceptedIssuers()
  {
    return new X509Certificate[0];
  }
}
