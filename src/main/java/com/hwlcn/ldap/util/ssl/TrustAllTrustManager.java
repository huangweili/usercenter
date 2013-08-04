package com.hwlcn.ldap.util.ssl;



import java.io.Serializable;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.net.ssl.X509TrustManager;

import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TrustAllTrustManager
       implements X509TrustManager, Serializable
{

  private static final long serialVersionUID = -1295254056169520318L;

  private final boolean examineValidityDates;


  public TrustAllTrustManager()
  {
    examineValidityDates = false;
  }


  public TrustAllTrustManager(final boolean examineValidityDates)
  {
    this.examineValidityDates = examineValidityDates;
  }




  public boolean examineValidityDates()
  {
    return examineValidityDates;
  }



  public void checkClientTrusted(final X509Certificate[] chain,
                                 final String authType)
         throws CertificateException
  {
    if (examineValidityDates)
    {
      final Date currentDate = new Date();

      for (final X509Certificate c : chain)
      {
        c.checkValidity(currentDate);
      }
    }
  }



  public void checkServerTrusted(final X509Certificate[] chain,
                                 final String authType)
         throws CertificateException
  {
    if (examineValidityDates)
    {
      final Date currentDate = new Date();

      for (final X509Certificate c : chain)
      {
        c.checkValidity(currentDate);
      }
    }
  }


  public X509Certificate[] getAcceptedIssuers()
  {
    return new X509Certificate[0];
  }
}
