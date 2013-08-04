
package com.hwlcn.ldap.ldap.matchingrules;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.matchingrules.MatchingRuleMessages.*;
import static com.hwlcn.ldap.util.StaticUtils.*;


@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TelephoneNumberMatchingRule
       extends SimpleMatchingRule
{

  private static final TelephoneNumberMatchingRule INSTANCE =
       new TelephoneNumberMatchingRule();



  public static final String EQUALITY_RULE_NAME = "telephoneNumberMatch";



  static final String LOWER_EQUALITY_RULE_NAME =
       toLowerCase(EQUALITY_RULE_NAME);


  public static final String EQUALITY_RULE_OID = "2.5.13.20";



  public static final String SUBSTRING_RULE_NAME =
       "telephoneNumberSubstringsMatch";



  static final String LOWER_SUBSTRING_RULE_NAME =
       toLowerCase(SUBSTRING_RULE_NAME);



  public static final String SUBSTRING_RULE_OID = "2.5.13.21";



  private static final long serialVersionUID = -5463096544849211252L;




  public TelephoneNumberMatchingRule()
  {

  }




  public static TelephoneNumberMatchingRule getInstance()
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
    return SUBSTRING_RULE_NAME;
  }



  @Override()
  public String getSubstringMatchingRuleOID()
  {
    return SUBSTRING_RULE_OID;
  }


  @Override()
  public int compareValues(final ASN1OctetString value1,
                           final ASN1OctetString value2)
         throws LDAPException
  {
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
         ERR_TELEPHONE_NUMBER_ORDERING_MATCHING_NOT_SUPPORTED.get());
  }



  @Override()
  public ASN1OctetString normalize(final ASN1OctetString value)
         throws LDAPException
  {
    final byte[] valueBytes = value.getValue();
    final StringBuilder buffer = new StringBuilder();
    for (int i=0; i < valueBytes.length; i++)
    {
      switch (valueBytes[i])
      {
        case ' ':
        case '-':

          break;

        case '\'':
        case '(':
        case ')':
        case '+':
        case ',':
        case '.':
        case '=':
        case '/':
        case ':':
        case '?':

          buffer.append((char) valueBytes[i]);
          break;

        default:
          final byte b = valueBytes[i];
          if (((b >= '0') && (b <= '9')) ||
              ((b >= 'a') && (b <= 'z')) ||
              ((b >= 'A') && (b <= 'Z')))
          {

            buffer.append((char) valueBytes[i]);
            break;
          }

          throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
               ERR_TELEPHONE_NUMBER_INVALID_CHARACTER.get(i));
      }
    }

    return new ASN1OctetString(buffer.toString());
  }


  @Override()
  public ASN1OctetString normalizeSubstring(final ASN1OctetString value,
                                            final byte substringType)
         throws LDAPException
  {
    return normalize(value);
  }
}
