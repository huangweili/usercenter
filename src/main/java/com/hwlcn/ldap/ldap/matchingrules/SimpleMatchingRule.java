
package com.hwlcn.ldap.ldap.matchingrules;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public abstract class SimpleMatchingRule
       extends MatchingRule
{

  private static final long serialVersionUID = -7221506185552250694L;


  @Override()
  public boolean valuesMatch(final ASN1OctetString value1,
                             final ASN1OctetString value2)
         throws LDAPException
  {
    return normalize(value1).equals(normalize(value2));
  }




  @Override()
  public boolean matchesSubstring(final ASN1OctetString value,
                                  final ASN1OctetString subInitial,
                                  final ASN1OctetString[] subAny,
                                  final ASN1OctetString subFinal)
         throws LDAPException
  {
    final byte[] normValue = normalize(value).getValue();

    int pos = 0;
    if (subInitial != null)
    {
      final byte[] normSubInitial =
           normalizeSubstring(subInitial, SUBSTRING_TYPE_SUBINITIAL).getValue();
      if (normValue.length < normSubInitial.length)
      {
        return false;
      }

      for (int i=0; i < normSubInitial.length; i++)
      {
        if (normValue[i] != normSubInitial[i])
        {
          return false;
        }
      }

      pos = normSubInitial.length;
    }

    if (subAny != null)
    {
      final byte[][] normSubAny = new byte[subAny.length][];
      for (int i=0; i < subAny.length; i++)
      {
        normSubAny[i] =
             normalizeSubstring(subAny[i],SUBSTRING_TYPE_SUBANY).getValue();
      }

      for (final byte[] b : normSubAny)
      {
        if (b.length == 0)
        {
          continue;
        }

        boolean match = false;
        final int subEndLength = normValue.length - b.length;
        while (pos <= subEndLength)
        {
          match = true;
          for (int i=0; i < b.length; i++)
          {
            if (normValue[pos+i] != b[i])
            {
              match = false;
              break;
            }
          }

          if (match)
          {
            pos += b.length;
            break;
          }
          else
          {
            pos++;
          }
        }

        if (! match)
        {
          return false;
        }
      }
    }

    if (subFinal != null)
    {
      final byte[] normSubFinal =
           normalizeSubstring(subFinal, SUBSTRING_TYPE_SUBFINAL).getValue();
      int finalStartPos = normValue.length - normSubFinal.length;
      if (finalStartPos < pos)
      {
        return false;
      }

      for (int i=0; i < normSubFinal.length; i++,finalStartPos++)
      {
        if (normValue[finalStartPos] != normSubFinal[i])
        {
          return false;
        }
      }
    }

    return true;
  }



  @Override()
  public int compareValues(final ASN1OctetString value1,
                           final ASN1OctetString value2)
         throws LDAPException
  {
    final byte[] normValue1 = normalize(value1).getValue();
    final byte[] normValue2 = normalize(value2).getValue();

    final int minLength = Math.min(normValue1.length, normValue2.length);
    for (int i=0; i < minLength; i++)
    {
      final int b1 = normValue1[i] & 0xFF;
      final int b2 = normValue2[i] & 0xFF;

      if (b1 < b2)
      {
        return -1;
      }
      else if (b1 > b2)
      {
        return 1;
      }
    }

    return normValue1.length - normValue2.length;
  }
}
