
package com.hwlcn.ldap.ldap.matchingrules;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;



@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class AcceptAllSimpleMatchingRule
       extends SimpleMatchingRule
{

  private static final long serialVersionUID = -7450007924568660003L;



  @Override()
  public boolean valuesMatch(final ASN1OctetString value1,
                             final ASN1OctetString value2)
  {
    return normalize(value1).equals(normalize(value2));
  }



  @Override()
  public boolean matchesSubstring(final ASN1OctetString value,
                                  final ASN1OctetString subInitial,
                                  final ASN1OctetString[] subAny,
                                  final ASN1OctetString subFinal)
  {
    try
    {
      return super.matchesSubstring(value, subInitial, subAny, subFinal);
    }
    catch (LDAPException le)
    {
      debugException(le);
      return false;
    }
  }


  @Override()
  public int compareValues(final ASN1OctetString value1,
                           final ASN1OctetString value2)
  {
    try
    {
      return super.compareValues(value1, value2);
    }
    catch (LDAPException le)
    {
      debugException(le);
      return 0;
    }
  }



  @Override()
  public abstract ASN1OctetString normalize(final ASN1OctetString value);



  @Override()
  public abstract ASN1OctetString normalizeSubstring(
                                       final ASN1OctetString value,
                                       final byte substringType);
}
