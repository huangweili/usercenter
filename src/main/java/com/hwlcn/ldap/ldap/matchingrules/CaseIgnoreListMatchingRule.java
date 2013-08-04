
package com.hwlcn.ldap.ldap.matchingrules;



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.matchingrules.MatchingRuleMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;



@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CaseIgnoreListMatchingRule
       extends MatchingRule
{

  private static final CaseIgnoreListMatchingRule INSTANCE =
       new CaseIgnoreListMatchingRule();




  public static final String EQUALITY_RULE_NAME = "caseIgnoreListMatch";




  static final String LOWER_EQUALITY_RULE_NAME =
       toLowerCase(EQUALITY_RULE_NAME);



  public static final String EQUALITY_RULE_OID = "2.5.13.11";


  public static final String SUBSTRING_RULE_NAME =
       "caseIgnoreListSubstringsMatch";



  static final String LOWER_SUBSTRING_RULE_NAME =
       toLowerCase(SUBSTRING_RULE_NAME);



  public static final String SUBSTRING_RULE_OID = "2.5.13.12";


  private static final long serialVersionUID = 7795143670808983466L;


  public CaseIgnoreListMatchingRule()
  {

  }



  public static CaseIgnoreListMatchingRule getInstance()
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
    String normStr = normalize(value).stringValue();

    if (subInitial != null)
    {
      final String normSubInitial = normalizeSubstring(subInitial,
           SUBSTRING_TYPE_SUBINITIAL).stringValue();
      if (normSubInitial.indexOf('$') >= 0)
      {
        throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
             ERR_CASE_IGNORE_LIST_SUBSTRING_COMPONENT_CONTAINS_DOLLAR.get(
                  normSubInitial));
      }

      if (! normStr.startsWith(normSubInitial))
      {
        return false;
      }

      normStr = normStr.substring(normSubInitial.length());
    }

    if (subFinal != null)
    {
      final String normSubFinal = normalizeSubstring(subFinal,
           SUBSTRING_TYPE_SUBFINAL).stringValue();
      if (normSubFinal.indexOf('$') >= 0)
      {
        throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
             ERR_CASE_IGNORE_LIST_SUBSTRING_COMPONENT_CONTAINS_DOLLAR.get(
                  normSubFinal));
      }

      if (! normStr.endsWith(normSubFinal))
      {

        return false;
      }

      normStr = normStr.substring(0, normStr.length() - normSubFinal.length());
    }

    if (subAny != null)
    {
      for (final ASN1OctetString s : subAny)
      {
        final String normSubAny =
             normalizeSubstring(s, SUBSTRING_TYPE_SUBANY).stringValue();
        if (normSubAny.indexOf('$') >= 0)
        {
          throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
               ERR_CASE_IGNORE_LIST_SUBSTRING_COMPONENT_CONTAINS_DOLLAR.get(
                    normSubAny));
        }

        final int pos = normStr.indexOf(normSubAny);
        if (pos < 0)
        {
          return false;
        }

        normStr = normStr.substring(pos + normSubAny.length());
      }
    }

    return true;
  }


  @Override()
  public int compareValues(final ASN1OctetString value1,
                           final ASN1OctetString value2)
         throws LDAPException
  {
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
         ERR_CASE_IGNORE_LIST_ORDERING_MATCHING_NOT_SUPPORTED.get());
  }

  @Override()
  public ASN1OctetString normalize(final ASN1OctetString value)
         throws LDAPException
  {
    final List<String>     items    = getLowercaseItems(value);
    final Iterator<String> iterator = items.iterator();

    final StringBuilder buffer = new StringBuilder();
    while (iterator.hasNext())
    {
      normalizeItem(buffer, iterator.next());
      if (iterator.hasNext())
      {
        buffer.append('$');
      }
    }

    return new ASN1OctetString(buffer.toString());
  }




  @Override()
  public ASN1OctetString normalizeSubstring(final ASN1OctetString value,
                                            final byte substringType)
         throws LDAPException
  {
    return CaseIgnoreStringMatchingRule.getInstance().normalizeSubstring(value,
         substringType);
  }



  public static List<String> getItems(final ASN1OctetString value)
         throws LDAPException
  {
    return getItems(value.stringValue());
  }




  public static List<String> getItems(final String value)
         throws LDAPException
  {
    final ArrayList<String> items = new ArrayList<String>(10);

    final int length = value.length();
    final StringBuilder buffer = new StringBuilder();
    for (int i=0; i < length; i++)
    {
      final char c = value.charAt(i);
      if (c == '\\')
      {
        try
        {
          buffer.append(decodeHexChar(value, i+1));
          i += 2;
        }
        catch (Exception e)
        {
          debugException(e);
          throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
               ERR_CASE_IGNORE_LIST_MALFORMED_HEX_CHAR.get(value), e);
        }
      }
      else if (c == '$')
      {
        final String s = buffer.toString().trim();
        if (s.length() == 0)
        {
          throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
               ERR_CASE_IGNORE_LIST_EMPTY_ITEM.get(value));
        }

        items.add(s);
        buffer.delete(0, buffer.length());
      }
      else
      {
        buffer.append(c);
      }
    }

    final String s = buffer.toString().trim();
    if (s.length() == 0)
    {
      if (items.isEmpty())
      {
        throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
             ERR_CASE_IGNORE_LIST_EMPTY_LIST.get(value));
      }
      else
      {
        throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                                ERR_CASE_IGNORE_LIST_EMPTY_ITEM.get(value));
      }
    }
    items.add(s);

    return Collections.unmodifiableList(items);
  }



  public static List<String> getLowercaseItems(final ASN1OctetString value)
         throws LDAPException
  {
    return getLowercaseItems(value.stringValue());
  }




  public static List<String> getLowercaseItems(final String value)
         throws LDAPException
  {
    return getItems(toLowerCase(value));
  }



  static void normalizeItem(final StringBuilder buffer, final String item)
  {
    final int length = item.length();

    boolean lastWasSpace = false;
    for (int i=0; i < length; i++)
    {
      final char c = item.charAt(i);
      if (c == '\\')
      {
        buffer.append("\\5c");
        lastWasSpace = false;
      }
      else if (c == '$')
      {
        buffer.append("\\24");
        lastWasSpace = false;
      }
      else if (c == ' ')
      {
        if (! lastWasSpace)
        {
          buffer.append(' ');
          lastWasSpace = true;
        }
      }
      else
      {
        buffer.append(c);
        lastWasSpace = false;
      }
    }
  }




  static char decodeHexChar(final String s, final int p)
         throws LDAPException
  {
    char c = 0;

    for (int i=0, j=p; (i < 2); i++,j++)
    {
      c <<= 4;

      switch (s.charAt(j))
      {
        case '0':
          break;
        case '1':
          c |= 0x01;
          break;
        case '2':
          c |= 0x02;
          break;
        case '3':
          c |= 0x03;
          break;
        case '4':
          c |= 0x04;
          break;
        case '5':
          c |= 0x05;
          break;
        case '6':
          c |= 0x06;
          break;
        case '7':
          c |= 0x07;
          break;
        case '8':
          c |= 0x08;
          break;
        case '9':
          c |= 0x09;
          break;
        case 'a':
        case 'A':
          c |= 0x0A;
          break;
        case 'b':
        case 'B':
          c |= 0x0B;
          break;
        case 'c':
        case 'C':
          c |= 0x0C;
          break;
        case 'd':
        case 'D':
          c |= 0x0D;
          break;
        case 'e':
        case 'E':
          c |= 0x0E;
          break;
        case 'f':
        case 'F':
          c |= 0x0F;
          break;
        default:
          throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
               ERR_CASE_IGNORE_LIST_NOT_HEX_DIGIT.get(s.charAt(j)));
      }
    }

    return c;
  }
}
