package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import com.hwlcn.ldap.ldap.sdk.DN;
import com.hwlcn.ldap.ldap.sdk.RDN;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPDN
{

  private LDAPDN()
  {
  }



  public static String normalize(final String dn)
  {
    try
    {
      return DN.normalize(dn);
    }
    catch (Exception e)
    {
      debugException(e);
      return toLowerCase(dn.trim());
    }
  }


  public static String[] explodeDN(final String dn, final boolean noTypes)
  {
    try
    {
      final RDN[] rdns = new DN(dn).getRDNs();
      final String[] rdnStrings = new String[rdns.length];
      for (int i=0; i < rdns.length; i++)
      {
        if (noTypes)
        {
          final StringBuilder buffer = new StringBuilder();
          for (final String s : rdns[i].getAttributeValues())
          {
            if (buffer.length() > 0)
            {
              buffer.append('+');
            }
            buffer.append(s);
          }
          rdnStrings[i] = buffer.toString();
        }
        else
        {
          rdnStrings[i] = rdns[i].toString();
        }
      }
      return rdnStrings;
    }
    catch (Exception e)
    {
      debugException(e);
      return new String[] { dn };
    }
  }



  public static String[] explodeRDN(final String rdn, final boolean noTypes)
  {
    try
    {
      final RDN      rdnObject  = new RDN(rdn);

      final String[] values = rdnObject.getAttributeValues();
      if (noTypes)
      {
        return values;
      }

      final String[] names      = rdnObject.getAttributeNames();
      final String[] returnStrs = new String[names.length];

      for (int i=0; i < names.length; i++)
      {
        returnStrs[i] = names[i] + '=' + values[i];
      }

      return returnStrs;
    }
    catch (Exception e)
    {
      debugException(e);
      return new String[] { rdn };
    }
  }

  public static boolean equals(final String dn1, final String dn2)
  {
    try
    {
      return DN.equals(dn1, dn2);
    }
    catch (Exception e)
    {
      debugException(e);
      return false;
    }
  }
}
