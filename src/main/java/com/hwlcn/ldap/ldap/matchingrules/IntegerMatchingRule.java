
package com.hwlcn.ldap.ldap.matchingrules;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.matchingrules.MatchingRuleMessages.*;
import static com.hwlcn.ldap.util.StaticUtils.*;



@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class IntegerMatchingRule
       extends MatchingRule
{

  private static final IntegerMatchingRule INSTANCE =
       new IntegerMatchingRule();


  public static final String EQUALITY_RULE_NAME = "integerMatch";



  static final String LOWER_EQUALITY_RULE_NAME =
       toLowerCase(EQUALITY_RULE_NAME);


  public static final String EQUALITY_RULE_OID = "2.5.13.14";


  public static final String ORDERING_RULE_NAME = "integerOrderingMatch";


  static final String LOWER_ORDERING_RULE_NAME =
       toLowerCase(ORDERING_RULE_NAME);


  public static final String ORDERING_RULE_OID = "2.5.13.15";


  private static final long serialVersionUID = -9056942146971528818L;


  public IntegerMatchingRule()
  {
  }




  public static IntegerMatchingRule getInstance()
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
                            ERR_INTEGER_SUBSTRING_MATCHING_NOT_SUPPORTED.get());
  }


  @Override()
  public int compareValues(final ASN1OctetString value1,
                           final ASN1OctetString value2)
         throws LDAPException
  {
    final byte[] norm1Bytes = normalize(value1).getValue();
    final byte[] norm2Bytes = normalize(value2).getValue();

    if (norm1Bytes[0] == '-')
    {
      if (norm2Bytes[0] == '-')
      {
        if (norm1Bytes.length < norm2Bytes.length)
        {
          return 1;
        }
        else if (norm1Bytes.length > norm2Bytes.length)
        {
          return -1;
        }
        else
        {
          for (int i=1; i < norm1Bytes.length; i++)
          {
            final int difference = norm2Bytes[i] - norm1Bytes[i];
            if (difference != 0)
            {
              return difference;
            }
          }

          return 0;
        }
      }
      else
      {
        return -1;
      }
    }
    else
    {
      if (norm2Bytes[0] == '-')
      {
        return 1;
      }
      else
      {
        if (norm1Bytes.length < norm2Bytes.length)
        {
          return -1;
        }
        else if (norm1Bytes.length > norm2Bytes.length)
        {
          return 1;
        }
        else
        {
          for (int i=0; i < norm1Bytes.length; i++)
          {
            final int difference = norm1Bytes[i] - norm2Bytes[i];
            if (difference != 0)
            {
              return difference;
            }
          }

          return 0;
        }
      }
    }
  }


  @Override()
  public ASN1OctetString normalize(final ASN1OctetString value)
         throws LDAPException
  {
    final byte[] valueBytes = value.getValue();
    if (valueBytes.length == 0)
    {
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                              ERR_INTEGER_ZERO_LENGTH_NOT_ALLOWED.get());
    }

    if ((valueBytes[0] == ' ') || (valueBytes[valueBytes.length-1] == ' '))
    {
      final String valueStr = value.stringValue().trim();
      if (valueStr.length() == 0)
      {
        throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                                ERR_INTEGER_ZERO_LENGTH_NOT_ALLOWED.get());
      }

      for (int i=0; i < valueStr.length(); i++)
      {
        switch (valueStr.charAt(i))
        {
          case '-':
            if ((i != 0) || (valueStr.length() == 1))
            {
              throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                                      ERR_INTEGER_INVALID_CHARACTER.get());
            }
            break;

          case '0':
            if (((i == 0) && (valueStr.length() > 1)) ||
                ((i == 1) && (valueStr.charAt(0) == '-')))
            {
              throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                                      ERR_INTEGER_INVALID_LEADING_ZERO.get());
            }
            break;

          case '1':
          case '2':
          case '3':
          case '4':
          case '5':
          case '6':
          case '7':
          case '8':
          case '9':
            // These are always acceptable.
            break;

          default:
            throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                                    ERR_INTEGER_INVALID_CHARACTER.get(i));
        }
      }

      return new ASN1OctetString(valueStr);
    }


    for (int i=0; i < valueBytes.length; i++)
    {
      switch (valueBytes[i])
      {
        case '-':
          if ((i != 0) || (valueBytes.length == 1))
          {
            throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                                    ERR_INTEGER_INVALID_CHARACTER.get());
          }
          break;

        case '0':
          if (((i == 0) && (valueBytes.length > 1)) ||
              ((i == 1) && (valueBytes[0] == '-')))
          {
            throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                                    ERR_INTEGER_INVALID_LEADING_ZERO.get());
          }
          break;

        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
          break;

        default:
          throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                                  ERR_INTEGER_INVALID_CHARACTER.get(i));
      }
    }

    return value;
  }



  @Override()
  public ASN1OctetString normalizeSubstring(final ASN1OctetString value,
                                            final byte substringType)
         throws LDAPException
  {
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
                            ERR_INTEGER_SUBSTRING_MATCHING_NOT_SUPPORTED.get());
  }
}
