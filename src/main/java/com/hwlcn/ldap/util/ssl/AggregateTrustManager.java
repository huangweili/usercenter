
package com.hwlcn.ldap.util.ssl;



import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.X509TrustManager;

import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;
import com.hwlcn.ldap.util.Validator;

import static com.hwlcn.ldap.util.Debug.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AggregateTrustManager
       implements X509TrustManager
{

  private static final X509Certificate[] NO_CERTIFICATES =
       new X509Certificate[0];


  private final boolean requireAllAccepted;

   private final List<X509TrustManager> trustManagers;


  public AggregateTrustManager(final boolean requireAllAccepted,
                               final X509TrustManager ... trustManagers)
  {
    this(requireAllAccepted, StaticUtils.toList(trustManagers));
  }


  public AggregateTrustManager(final boolean requireAllAccepted,
              final Collection<X509TrustManager > trustManagers)
  {
    Validator.ensureNotNull(trustManagers);
    Validator.ensureFalse(trustManagers.isEmpty(),
         "The set of associated trust managers must not be empty.");

    this.requireAllAccepted = requireAllAccepted;
    this.trustManagers = Collections.unmodifiableList(
         new ArrayList<X509TrustManager>(trustManagers));
  }



  public boolean requireAllAccepted()
  {
    return requireAllAccepted;
  }



  public List<X509TrustManager> getAssociatedTrustManagers()
  {
    return trustManagers;
  }

  public void checkClientTrusted(final X509Certificate[] chain,
                                 final String authType)
         throws CertificateException
  {
    ArrayList<String> exceptionMessages = null;

    for (final X509TrustManager m : trustManagers)
    {
      try
      {
        m.checkClientTrusted(chain, authType);

        if (! requireAllAccepted)
        {
          return;
        }
      }
      catch (final CertificateException ce)
      {
        debugException(ce);

        if (requireAllAccepted)
        {
          throw ce;
        }
        else
        {
          if (exceptionMessages == null)
          {
            exceptionMessages = new ArrayList<String>(trustManagers.size());
          }

          exceptionMessages.add(ce.getMessage());
        }
      }
    }


    if ((exceptionMessages != null) && (! exceptionMessages.isEmpty()))
    {
      throw new CertificateException(
           StaticUtils.concatenateStrings(exceptionMessages));
    }
  }


  public void checkServerTrusted(final X509Certificate[] chain,
                                 final String authType)
         throws CertificateException
  {
    ArrayList<String> exceptionMessages = null;

    for (final X509TrustManager m : trustManagers)
    {
      try
      {
        m.checkServerTrusted(chain, authType);

        if (! requireAllAccepted)
        {
          return;
        }
      }
      catch (final CertificateException ce)
      {
        debugException(ce);

        if (requireAllAccepted)
        {
          throw ce;
        }
        else
        {
          if (exceptionMessages == null)
          {
            exceptionMessages = new ArrayList<String>(trustManagers.size());
          }

          exceptionMessages.add(ce.getMessage());
        }
      }
    }

    if ((exceptionMessages != null) && (! exceptionMessages.isEmpty()))
    {
      throw new CertificateException(
           StaticUtils.concatenateStrings(exceptionMessages));
    }
  }


  public X509Certificate[] getAcceptedIssuers()
  {
    return NO_CERTIFICATES;
  }
}
