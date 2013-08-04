
package com.hwlcn.ldap.ldap.matchingrules;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.matchingrules.MatchingRuleMessages.*;
import static com.hwlcn.ldap.util.StaticUtils.*;



@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class BooleanMatchingRule
       extends MatchingRule
{

  private static final BooleanMatchingRule INSTANCE =
       new BooleanMatchingRule();



  private static final ASN1OctetString TRUE_VALUE = new ASN1OctetString("TRUE");



  private static final ASN1OctetString FALSE_VALUE =
       new ASN1OctetString("FALSE");




  public static final String EQUALITY_RULE_NAME = "booleanMatch";



  static final String LOWER_EQUALITY_RULE_NAME =
       toLowerCase(EQUALITY_RULE_NAME);


  public static final String EQUALITY_RULE_OID = "2.5.13.13";


  private static final long serialVersionUID = 5137725892611277972L;


  public BooleanMatchingRule()
  {

  }



  public static BooleanMatchingRule getInstance()
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
    return normalize(value1).equals(normalize(value2));
  }

  @Override()
  public boolean matchesSubstring(final ASN1OctetString value,
                                  final ASN1OctetString subInitial,
                                  final ASN1OctetString[] subAny,
                                  final ASN1OctetString subFinal)
         throws LDAPException
  {
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
                            ERR_BOOLEAN_SUBSTRING_MATCHING_NOT_SUPPORTED.get());
  }


  @Override()
  public int compareValues(final ASN1OctetString value1,
                           final ASN1OctetString value2)
         throws LDAPException
  {
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
                            ERR_BOOLEAN_ORDERING_MATCHING_NOT_SUPPORTED.get());
  }


  @Override()
  public ASN1OctetString normalize(final ASN1OctetString value)
         throws LDAPException
  {
    final byte[] valueBytes = value.getValue();

    if ((valueBytes.length == 4) &&
        ((valueBytes[0] == 'T') || (valueBytes[0] == 't')) &&
        ((valueBytes[1] == 'R') || (valueBytes[1] == 'r')) &&
        ((valueBytes[2] == 'U') || (valueBytes[2] == 'u')) &&
        ((valueBytes[3] == 'E') || (valueBytes[3] == 'e')))
    {
      return TRUE_VALUE;
    }
    else if ((valueBytes.length == 5) &&
             ((valueBytes[0] == 'F') || (valueBytes[0] == 'f')) &&
             ((valueBytes[1] == 'A') || (valueBytes[1] == 'a')) &&
             ((valueBytes[2] == 'L') || (valueBytes[2] == 'l')) &&
             ((valueBytes[3] == 'S') || (valueBytes[3] == 's')) &&
             ((valueBytes[4] == 'E') || (valueBytes[4] == 'e')))
    {
      return FALSE_VALUE;
    }
    else
    {
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                              ERR_BOOLEAN_INVALID_VALUE.get());
    }
  }



  @Override()
  public ASN1OctetString normalizeSubstring(final ASN1OctetString value,
                                            final byte substringType)
         throws LDAPException
  {
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
                            ERR_BOOLEAN_SUBSTRING_MATCHING_NOT_SUPPORTED.get());
  }
}
