
package com.hwlcn.ldap.util.ssl;



import java.net.InetAddress;
import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import com.hwlcn.ldap.ldap.sdk.DN;
import com.hwlcn.ldap.ldap.sdk.RDN;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;
import com.hwlcn.ldap.util.Validator;

import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.ssl.SSLMessages.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class HostNameTrustManager
       implements X509TrustManager
{
  private static final X509Certificate[] NO_CERTIFICATES =
       new X509Certificate[0];



  private final boolean allowWildcards;

  private final Set<String> acceptableHostNames;



  public HostNameTrustManager(final boolean allowWildcards,
                              final String... acceptableHostNames)
  {
    this(allowWildcards, StaticUtils.toList(acceptableHostNames));
  }


  public HostNameTrustManager(final boolean allowWildcards,
                              final Collection<String> acceptableHostNames)
  {
    Validator.ensureNotNull(acceptableHostNames);
    Validator.ensureFalse(acceptableHostNames.isEmpty(),
         "The set of acceptable host names must not be empty.");

    this.allowWildcards = allowWildcards;

    final LinkedHashSet<String> nameSet =
         new LinkedHashSet<String>(acceptableHostNames.size());
    for (final String s : acceptableHostNames)
    {
      nameSet.add(StaticUtils.toLowerCase(s));
    }

    this.acceptableHostNames = Collections.unmodifiableSet(nameSet);
  }


  public boolean allowWildcards()
  {
    return allowWildcards;
  }


  public Set<String> getAcceptableHostNames()
  {
    return acceptableHostNames;
  }



  public void checkClientTrusted(final X509Certificate[] chain,
                                 final String authType)
         throws CertificateException
  {
    checkCertificate(chain[0]);
  }


  public void checkServerTrusted(final X509Certificate[] chain,
                                 final String authType)
         throws CertificateException
  {
    checkCertificate(chain[0]);
  }


  private void checkCertificate(final X509Certificate c)
          throws CertificateException
  {
    final String subjectDN =
         c.getSubjectX500Principal().getName(X500Principal.RFC2253);
    try
    {
      final DN dn = new DN(subjectDN);
      for (final RDN rdn : dn.getRDNs())
      {
        final String[] names  = rdn.getAttributeNames();
        final String[] values = rdn.getAttributeValues();
        for (int i=0; i < names.length; i++)
        {
          final String lowerName = StaticUtils.toLowerCase(names[i]);
          if (lowerName.equals("cn") || lowerName.equals("commonname") ||
              lowerName.equals("2.5.4.3"))
          {
            final String lowerValue = StaticUtils.toLowerCase(values[i]);
            if (acceptableHostNames.contains(lowerValue))
            {
              return;
            }

            if (allowWildcards && lowerValue.startsWith("*."))
            {
              final String withoutWildcard = lowerValue.substring(1);
              for (final String s : acceptableHostNames)
              {
                if (s.endsWith(withoutWildcard))
                {
                  return;
                }
              }
            }
          }
        }
      }
    }
    catch (final Exception e)
    {
      debugException(e);
    }


    final Collection<List<?>> subjectAltNames = c.getSubjectAlternativeNames();
    if (subjectAltNames != null)
    {
      for (final List<?> l : subjectAltNames)
      {
        try
        {
          final Integer type = (Integer) l.get(0);
          switch (type)
          {
            case 2:
              final String dnsName = StaticUtils.toLowerCase((String) l.get(1));
              if (acceptableHostNames.contains(dnsName))
              {
                return;
              }

              if (allowWildcards && dnsName.startsWith("*."))
              {
                final String withoutWildcard = dnsName.substring(1);
                for (final String s : acceptableHostNames)
                {
                  if (s.endsWith(withoutWildcard))
                  {
                    return;
                  }
                }
              }
              break;

            case 6:
              final URI uri = new URI((String) l.get(1));
              if (acceptableHostNames.contains(
                   StaticUtils.toLowerCase(uri.getHost())))
              {

                return;
              }
              break;

            case 7:
              final InetAddress inetAddress =
                   InetAddress.getByName((String) l.get(1));
              for (final String s : acceptableHostNames)
              {
                if (Character.isDigit(s.charAt(0)) || (s.indexOf(':') >= 0))
                {
                  final InetAddress a = InetAddress.getByName(s);
                  if (inetAddress.equals(a))
                  {
                    return;
                  }
                }
              }
              break;

            case 0:
            case 1:
            case 3:
            case 4:
            case 5:
            case 8:
            default:

              break;
          }
        }
        catch (final Exception e)
        {
          debugException(e);
        }
      }
    }

    throw new CertificateException(ERR_HOSTNAME_NOT_FOUND.get(subjectDN));
  }


  public X509Certificate[] getAcceptedIssuers()
  {
    return NO_CERTIFICATES;
  }
}
