
package com.hwlcn.ldap.ldap.matchingrules;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.DN;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.matchingrules.MatchingRuleMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;




@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DistinguishedNameMatchingRule
       extends MatchingRule
{

  private static final DistinguishedNameMatchingRule INSTANCE =
       new DistinguishedNameMatchingRule();



  public static final String EQUALITY_RULE_NAME = "distinguishedNameMatch";



  static final String LOWER_EQUALITY_RULE_NAME =
       toLowerCase(EQUALITY_RULE_NAME);


  public static final String EQUALITY_RULE_OID = "2.5.13.1";



  private static final long serialVersionUID = -2617356571703597868L;



  public DistinguishedNameMatchingRule()
  {

  }




  public static DistinguishedNameMatchingRule getInstance()
  {
    return INSTANCE;
  }


  @Override()
  public String getEqualityMatchingRuleName()
  {
    return EQUALITY_RULE_NAME;
  }



  @Override()
  public String getEqualityMatchingRuleOID()
  {
    return EQUALITY_RULE_OID;
  }


  @Override()
  public String getOrderingMatchingRuleName()
  {
    return null;
  }



  @Override()
  public String getOrderingMatchingRuleOID()
  {
    return null;
  }



  @Override()
  public String getSubstringMatchingRuleName()
  {
    return null;
  }



  @Override()
  public String getSubstringMatchingRuleOID()
  {
    return null;
  }



  @Override()
  public boolean valuesMatch(final ASN1OctetString value1,
                             final ASN1OctetString value2)
         throws LDAPException
  {
    final DN dn1;
    try
    {
      dn1 = new DN(value1.stringValue());
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                              le.getMessage(), le);
    }

    final DN dn2;
    try
    {
      dn2 = new DN(value2.stringValue());
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                              le.getMessage(), le);
    }

    return dn1.equals(dn2);
  }



  @Override()
  public boolean matchesSubstring(final ASN1OctetString value,
                                  final ASN1OctetString subInitial,
                                  final ASN1OctetString[] subAny,
                                  final ASN1OctetString subFinal)
         throws LDAPException
  {
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
                            ERR_DN_SUBSTRING_MATCHING_NOT_SUPPORTED.get());
  }



  @Override()
  public int compareValues(final ASN1OctetString value1,
                           final ASN1OctetString value2)
         throws LDAPException
  {
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
                            ERR_DN_ORDERING_MATCHING_NOT_SUPPORTED.get());
  }




  @Override()
  public ASN1OctetString normalize(final ASN1OctetString value)
         throws LDAPException
  {
    try
    {
      final DN dn = new DN(value.stringValue());
      return new ASN1OctetString(dn.toNormalizedString());
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                              le.getMessage(), le);
    }
  }


  @Override()
  public ASN1OctetString normalizeSubstring(final ASN1OctetString value,
                                            final byte substringType)
         throws LDAPException
  {
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
                            ERR_DN_SUBSTRING_MATCHING_NOT_SUPPORTED.get());
  }
}
