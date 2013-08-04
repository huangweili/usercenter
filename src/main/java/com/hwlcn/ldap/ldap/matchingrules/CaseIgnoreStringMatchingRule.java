
package com.hwlcn.ldap.ldap.matchingrules;



import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.StaticUtils.*;


@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CaseIgnoreStringMatchingRule
       extends AcceptAllSimpleMatchingRule
{

  private static final CaseIgnoreStringMatchingRule INSTANCE =
       new CaseIgnoreStringMatchingRule();



  public static final String EQUALITY_RULE_NAME = "caseIgnoreMatch";



  static final String LOWER_EQUALITY_RULE_NAME =
       toLowerCase(EQUALITY_RULE_NAME);



  public static final String EQUALITY_RULE_OID = "2.5.13.2";



  public static final String ORDERING_RULE_NAME = "caseIgnoreOrderingMatch";


  static final String LOWER_ORDERING_RULE_NAME =
       toLowerCase(ORDERING_RULE_NAME);


  public static final String ORDERING_RULE_OID = "2.5.13.3";



  public static final String SUBSTRING_RULE_NAME = "caseIgnoreSubstringsMatch";



  static final String LOWER_SUBSTRING_RULE_NAME =
       toLowerCase(SUBSTRING_RULE_NAME);



  public static final String SUBSTRING_RULE_OID = "2.5.13.4";



  private static final long serialVersionUID = -1293370922676445525L;



  public CaseIgnoreStringMatchingRule()
  {
  }



  public static CaseIgnoreStringMatchingRule getInstance()
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
  public boolean valuesMatch(final ASN1OctetString value1,
                             final ASN1OctetString value2)
  {
   final byte[] value1Bytes = value1.getValue();
    final byte[] value2Bytes = value2.getValue();
    if (value1Bytes.length == value2Bytes.length)
    {
      for (int i=0; i< value1Bytes.length; i++)
      {
        final byte b1 = value1Bytes[i];
        final byte b2 = value2Bytes[i];

        if (((b1 & 0x7F) != (b1 & 0xFF)) ||
            ((b2 & 0x7F) != (b2 & 0xFF)))
        {
          return normalize(value1).equals(normalize(value2));
        }
        else if (b1 != b2)
        {
          if ((b1 == ' ') || (b2 == ' '))
          {
            return normalize(value1).equals(normalize(value2));
          }
          else if (Character.isUpperCase((char) b1))
          {
            final char c = Character.toLowerCase((char) b1);
            if (c != ((char) b2))
            {
              return false;
            }
          }
          else if (Character.isUpperCase((char) b2))
          {
            final char c = Character.toLowerCase((char) b2);
            if (c != ((char) b1))
            {
              return false;
            }
          }
          else
          {
            return false;
          }
        }
      }

      return true;
    }
    else
    {
      return normalizeInternal(value1, false, (byte) 0x00).equals(
                  normalizeInternal(value2, false, (byte) 0x00));
    }
  }




  @Override()
  public ASN1OctetString normalize(final ASN1OctetString value)
  {
    return normalizeInternal(value, false, (byte) 0x00);
  }



  @Override()
  public ASN1OctetString normalizeSubstring(final ASN1OctetString value,
                                            final byte substringType)
  {
    return normalizeInternal(value, true, substringType);
  }




  private static ASN1OctetString normalizeInternal(final ASN1OctetString value,
                                                   final boolean isSubstring,
                                                   final byte substringType)
  {
    final byte[] valueBytes = value.getValue();
    if (valueBytes.length == 0)
    {
      return value;
    }

    final boolean trimInitial;
    final boolean trimFinal;
    if (isSubstring)
    {
      switch (substringType)
      {
        case SUBSTRING_TYPE_SUBINITIAL:
          trimInitial = true;
          trimFinal   = false;
          break;

        case SUBSTRING_TYPE_SUBFINAL:
          trimInitial = false;
          trimFinal   = true;
          break;

        default:
          trimInitial = false;
          trimFinal   = false;
          break;
      }
    }
    else
    {
      trimInitial = true;
      trimFinal   = true;
    }


    boolean containsNonSpace = false;
    boolean lastWasSpace = trimInitial;
    int numDuplicates = 0;
    for (final byte b : valueBytes)
    {
      if ((b & 0x7F) != (b & 0xFF))
      {
        return normalizeNonASCII(value, trimInitial, trimFinal);
      }

      if (b == ' ')
      {
        if (lastWasSpace)
        {
          numDuplicates++;
        }
        else
        {
          lastWasSpace = true;
        }
      }
      else
      {
        containsNonSpace = true;
        lastWasSpace = false;
      }
    }

    if (! containsNonSpace)
    {
      return new ASN1OctetString(" ");
    }

    if (lastWasSpace && trimFinal)
    {
      numDuplicates++;
    }


    lastWasSpace = trimInitial;
    int targetPos = 0;
    final byte[] normalizedBytes = new byte[valueBytes.length - numDuplicates];
    for (int i=0; i < valueBytes.length; i++)
    {
      switch (valueBytes[i])
      {
        case ' ':
          if (lastWasSpace || (trimFinal && (i == (valueBytes.length - 1))))
          {
          }
          else
          {
            if (targetPos < normalizedBytes.length)
            {
              normalizedBytes[targetPos++] = ' ';
              lastWasSpace = true;
            }
          }

          break;
        case 'A':
          normalizedBytes[targetPos++] = 'a';
          lastWasSpace = false;
          break;
        case 'B':
          normalizedBytes[targetPos++] = 'b';
          lastWasSpace = false;
          break;
        case 'C':
          normalizedBytes[targetPos++] = 'c';
          lastWasSpace = false;
          break;
        case 'D':
          normalizedBytes[targetPos++] = 'd';
          lastWasSpace = false;
          break;
        case 'E':
          normalizedBytes[targetPos++] = 'e';
          lastWasSpace = false;
          break;
        case 'F':
          normalizedBytes[targetPos++] = 'f';
          lastWasSpace = false;
          break;
        case 'G':
          normalizedBytes[targetPos++] = 'g';
          lastWasSpace = false;
          break;
        case 'H':
          normalizedBytes[targetPos++] = 'h';
          lastWasSpace = false;
          break;
        case 'I':
          normalizedBytes[targetPos++] = 'i';
          lastWasSpace = false;
          break;
        case 'J':
          normalizedBytes[targetPos++] = 'j';
          lastWasSpace = false;
          break;
        case 'K':
          normalizedBytes[targetPos++] = 'k';
          lastWasSpace = false;
          break;
        case 'L':
          normalizedBytes[targetPos++] = 'l';
          lastWasSpace = false;
          break;
        case 'M':
          normalizedBytes[targetPos++] = 'm';
          lastWasSpace = false;
          break;
        case 'N':
          normalizedBytes[targetPos++] = 'n';
          lastWasSpace = false;
          break;
        case 'O':
          normalizedBytes[targetPos++] = 'o';
          lastWasSpace = false;
          break;
        case 'P':
          normalizedBytes[targetPos++] = 'p';
          lastWasSpace = false;
          break;
        case 'Q':
          normalizedBytes[targetPos++] = 'q';
          lastWasSpace = false;
          break;
        case 'R':
          normalizedBytes[targetPos++] = 'r';
          lastWasSpace = false;
          break;
        case 'S':
          normalizedBytes[targetPos++] = 's';
          lastWasSpace = false;
          break;
        case 'T':
          normalizedBytes[targetPos++] = 't';
          lastWasSpace = false;
          break;
        case 'U':
          normalizedBytes[targetPos++] = 'u';
          lastWasSpace = false;
          break;
        case 'V':
          normalizedBytes[targetPos++] = 'v';
          lastWasSpace = false;
          break;
        case 'W':
          normalizedBytes[targetPos++] = 'w';
          lastWasSpace = false;
          break;
        case 'X':
          normalizedBytes[targetPos++] = 'x';
          lastWasSpace = false;
          break;
        case 'Y':
          normalizedBytes[targetPos++] = 'y';
          lastWasSpace = false;
          break;
        case 'Z':
          normalizedBytes[targetPos++] = 'z';
          lastWasSpace = false;
          break;
        default:
          normalizedBytes[targetPos++] = valueBytes[i];
          lastWasSpace = false;
          break;
      }
    }


    return new ASN1OctetString(normalizedBytes);
  }



  private static ASN1OctetString normalizeNonASCII(final ASN1OctetString value,
                                                   final boolean trimInitial,
                                                   final boolean trimFinal)
  {
    final StringBuilder buffer = new StringBuilder(value.stringValue());

    int pos = 0;
    boolean lastWasSpace = trimInitial;
    while (pos < buffer.length())
    {
      final char c = buffer.charAt(pos++);
      if (c == ' ')
      {
        if (lastWasSpace || (trimFinal && (pos >= buffer.length())))
        {
          buffer.deleteCharAt(--pos);
        }
        else
        {
          lastWasSpace = true;
        }
      }
      else
      {
        if (Character.isUpperCase(c))
        {
          buffer.setCharAt((pos-1), Character.toLowerCase(c));
        }

        lastWasSpace = false;
      }
    }

    if (trimFinal && (buffer.length() > 0) &&
        (buffer.charAt(buffer.length() - 1) == ' '))
    {
      buffer.deleteCharAt(buffer.length() - 1);
    }

    return new ASN1OctetString(buffer.toString());
  }
}
