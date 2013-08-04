
package com.hwlcn.ldap.ldap.matchingrules;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.matchingrules.MatchingRuleMessages.*;
import static com.hwlcn.ldap.util.StaticUtils.*;

@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class NumericStringMatchingRule
       extends SimpleMatchingRule
{

  private static final NumericStringMatchingRule INSTANCE =
       new NumericStringMatchingRule();




  public static final String EQUALITY_RULE_NAME = "numericStringMatch";



  static final String LOWER_EQUALITY_RULE_NAME =
       toLowerCase(EQUALITY_RULE_NAME);




  public static final String EQUALITY_RULE_OID = "2.5.13.8";



  public static final String ORDERING_RULE_NAME = "numericStringOrderingMatch";


  static final String LOWER_ORDERING_RULE_NAME =
       toLowerCase(ORDERING_RULE_NAME);


  public static final String ORDERING_RULE_OID = "2.5.13.9";


  public static final String SUBSTRING_RULE_NAME =
       "numericStringSubstringsMatch";


  static final String LOWER_SUBSTRING_RULE_NAME =
       toLowerCase(SUBSTRING_RULE_NAME);



  public static final String SUBSTRING_RULE_OID = "2.5.13.10";



  private static final long serialVersionUID = -898484312052746321L;



  public NumericStringMatchingRule()
  {
  }



  public static NumericStringMatchingRule getInstance()
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
    return ORDERING_RULE_NAME;
  }



  @Override()
  public String getOrderingMatchingRuleOID()
  {
    return ORDERING_RULE_OID;
  }



  @Override()
  public String getSubstringMatchingRuleName()
  {
    return SUBSTRING_RULE_NAME;
  }


  @Override()
  public String getSubstringMatchingRuleOID()
  {
    return SUBSTRING_RULE_OID;
  }



  @Override()
  public ASN1OctetString normalize(final ASN1OctetString value)
         throws LDAPException
  {

    int numSpaces = 0;
    final byte[] valueBytes = value.getValue();
    for (int i=0; i < valueBytes.length; i++)
    {
      if (valueBytes[i] == ' ')
      {
        numSpaces++;
      }
      else if ((valueBytes[i] < '0') || (valueBytes[i] > '9'))
      {
        throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                                ERR_NUMERIC_STRING_INVALID_CHARACTER.get(i));
      }
    }

    if (numSpaces == 0)
    {
      return value;
    }

    int pos = 0;
    final byte[] returnBytes = new byte[valueBytes.length-numSpaces];
    for (final byte b : valueBytes)
    {
      if (b != ' ')
      {
        returnBytes[pos++] = b;
      }
    }

    return new ASN1OctetString(returnBytes);
  }


  @Override()
  public ASN1OctetString normalizeSubstring(final ASN1OctetString value,
                                            final byte substringType)
         throws LDAPException
  {
    return normalize(value);
  }
}
