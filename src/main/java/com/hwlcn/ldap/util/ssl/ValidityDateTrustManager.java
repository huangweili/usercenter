
package com.hwlcn.ldap.util.ssl;



import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.ssl.SSLMessages.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ValidityDateTrustManager
       implements X509TrustManager
{

  private static final X509Certificate[] NO_CERTIFICATES =
       new X509Certificate[0];

  public ValidityDateTrustManager()
  {
    // No implementation is required.
  }


  public void checkClientTrusted(final X509Certificate[] chain,
                                 final String authType)
         throws CertificateException
  {
    checkCertificateValidity(chain[0]);
  }

  public void checkServerTrusted(final X509Certificate[] chain,
                                 final String authType)
         throws CertificateException
  {
    checkCertificateValidity(chain[0]);
  }

  private static void checkCertificateValidity(final X509Certificate c)
         throws CertificateException
  {
    final Date currentTime = new Date();
    final Date notBefore   = c.getNotBefore();
    final Date notAfter    = c.getNotAfter();

    if (currentTime.before(notBefore))
    {
      throw new CertificateException(ERR_VALIDITY_TOO_EARLY.get(
           c.getSubjectX500Principal().getName(X500Principal.RFC2253),
           String.valueOf(notBefore)));
    }

    if (currentTime.after(c.getNotAfter()))
    {
      throw new CertificateException(ERR_VALIDITY_TOO_LATE.get(
           c.getSubjectX500Principal().getName(X500Principal.RFC2253),
           String.valueOf(notAfter)));
    }
  }

  public X509Certificate[] getAcceptedIssuers()
  {
    return NO_CERTIFICATES;
  }
}
