package com.hwlcn.ldap.ldap.matchingrules;



import java.io.Serializable;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.schema.AttributeTypeDefinition;
import com.hwlcn.ldap.ldap.sdk.schema.Schema;
import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.StaticUtils.*;



@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class MatchingRule
       implements Serializable
{

  public static final byte SUBSTRING_TYPE_SUBINITIAL = (byte) 0x80;


  public static final byte SUBSTRING_TYPE_SUBANY = (byte) 0x81;

  public static final byte SUBSTRING_TYPE_SUBFINAL = (byte) 0x82;

  private static final long serialVersionUID = 6050276733546358513L;

  protected MatchingRule()
  {
  }


  public abstract String getEqualityMatchingRuleName();


  public abstract String getEqualityMatchingRuleOID();

  public String getEqualityMatchingRuleNameOrOID()
  {
    final String name = getEqualityMatchingRuleName();
    if (name == null)
    {
      return getEqualityMatchingRuleOID();
    }
    else
    {
      return name;
    }
  }


  public abstract String getOrderingMatchingRuleName();

  public abstract String getOrderingMatchingRuleOID();



  public String getOrderingMatchingRuleNameOrOID()
  {
    final String name = getOrderingMatchingRuleName();
    if (name == null)
    {
      return getOrderingMatchingRuleOID();
    }
    else
    {
      return name;
    }
  }

  public abstract String getSubstringMatchingRuleName();

  public abstract String getSubstringMatchingRuleOID();

  public String getSubstringMatchingRuleNameOrOID()
  {
    final String name = getSubstringMatchingRuleName();
    if (name == null)
    {
      return getSubstringMatchingRuleOID();
    }
    else
    {
      return name;
    }
  }

  public abstract boolean valuesMatch(final ASN1OctetString value1,
                                      final ASN1OctetString value2)
         throws LDAPException;


  public abstract boolean matchesSubstring(final ASN1OctetString value,
                                           final ASN1OctetString subInitial,
                                           final ASN1OctetString[] subAny,
                                           final ASN1OctetString subFinal)
         throws LDAPException;


  public abstract int compareValues(final ASN1OctetString value1,
                                    final ASN1OctetString value2)
         throws LDAPException;


  public abstract ASN1OctetString normalize(final ASN1OctetString value)
         throws LDAPException;



  public abstract ASN1OctetString normalizeSubstring(
                                       final ASN1OctetString value,
                                       final byte substringType)
         throws LDAPException;




  public static MatchingRule selectEqualityMatchingRule(final String attrName,
                                                        final Schema schema)
  {
    return selectEqualityMatchingRule(attrName, null, schema);
  }




  public static MatchingRule selectEqualityMatchingRule(final String attrName,
                                  final String ruleID, final Schema schema)
  {
    if (ruleID != null)
    {
      return selectEqualityMatchingRule(ruleID);
    }

    if ((attrName == null) || (schema == null))
    {
      return getDefaultEqualityMatchingRule();
    }

    final AttributeTypeDefinition attrType = schema.getAttributeType(attrName);
    if (attrType == null)
    {
      return getDefaultEqualityMatchingRule();
    }

    final String mrName = attrType.getEqualityMatchingRule(schema);
    if (mrName != null)
    {
      return selectEqualityMatchingRule(mrName);
    }

    final String syntaxOID = attrType.getBaseSyntaxOID(schema);
    if (syntaxOID != null)
    {
      return selectMatchingRuleForSyntax(syntaxOID);
    }

    return getDefaultEqualityMatchingRule();
  }



  public static MatchingRule selectEqualityMatchingRule(final String ruleID)
  {
    if ((ruleID == null) || (ruleID.length() == 0))
    {
      return getDefaultEqualityMatchingRule();
    }

    final String lowerName = toLowerCase(ruleID);
    if (lowerName.equals(BooleanMatchingRule.LOWER_EQUALITY_RULE_NAME) ||
        lowerName.equals(BooleanMatchingRule.EQUALITY_RULE_OID))
    {
      return BooleanMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  CaseExactStringMatchingRule.LOWER_EQUALITY_RULE_NAME) ||
             lowerName.equals(CaseExactStringMatchingRule.EQUALITY_RULE_OID) ||
             lowerName.equals("caseexactia5match") ||
             lowerName.equals("1.3.6.1.4.1.1466.109.114.1"))
    {
      return CaseExactStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  CaseIgnoreListMatchingRule.LOWER_EQUALITY_RULE_NAME) ||
             lowerName.equals(CaseIgnoreListMatchingRule.EQUALITY_RULE_OID))
    {
      return CaseIgnoreListMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  CaseIgnoreStringMatchingRule.LOWER_EQUALITY_RULE_NAME) ||
             lowerName.equals(CaseIgnoreStringMatchingRule.EQUALITY_RULE_OID) ||
             lowerName.equals("caseignoreia5match") ||
             lowerName.equals("1.3.6.1.4.1.1466.109.114.2"))
    {
      return CaseIgnoreStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  DistinguishedNameMatchingRule.LOWER_EQUALITY_RULE_NAME) ||
             lowerName.equals(
                  DistinguishedNameMatchingRule.EQUALITY_RULE_OID) ||
             lowerName.equals("uniquemembermatch") ||
             lowerName.equals("2.5.13.23"))
    {

      return DistinguishedNameMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  GeneralizedTimeMatchingRule.LOWER_EQUALITY_RULE_NAME) ||
             lowerName.equals(GeneralizedTimeMatchingRule.EQUALITY_RULE_OID))
    {
      return GeneralizedTimeMatchingRule.getInstance();
    }
    else if (lowerName.equals(IntegerMatchingRule.LOWER_EQUALITY_RULE_NAME) ||
             lowerName.equals(IntegerMatchingRule.EQUALITY_RULE_OID))
    {
      return IntegerMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  NumericStringMatchingRule.LOWER_EQUALITY_RULE_NAME) ||
             lowerName.equals(NumericStringMatchingRule.EQUALITY_RULE_OID))
    {
      return NumericStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  OctetStringMatchingRule.LOWER_EQUALITY_RULE_NAME) ||
             lowerName.equals(OctetStringMatchingRule.EQUALITY_RULE_OID))
    {
      return OctetStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  TelephoneNumberMatchingRule.LOWER_EQUALITY_RULE_NAME) ||
             lowerName.equals(TelephoneNumberMatchingRule.EQUALITY_RULE_OID))
    {
      return TelephoneNumberMatchingRule.getInstance();
    }
    else
    {
      return getDefaultEqualityMatchingRule();
    }
  }

  public static MatchingRule getDefaultEqualityMatchingRule()
  {
    return CaseIgnoreStringMatchingRule.getInstance();
  }


  public static MatchingRule selectOrderingMatchingRule(final String attrName,
                                                        final Schema schema)
  {
    return selectOrderingMatchingRule(attrName, null, schema);
  }


  public static MatchingRule selectOrderingMatchingRule(final String attrName,
                                                        final String ruleID,
                                                        final Schema schema)
  {
    if (ruleID != null)
    {
      return selectOrderingMatchingRule(ruleID);
    }

    if ((attrName == null) || (schema == null))
    {
      return getDefaultOrderingMatchingRule();
    }

    final AttributeTypeDefinition attrType = schema.getAttributeType(attrName);
    if (attrType == null)
    {
      return getDefaultOrderingMatchingRule();
    }

    final String mrName = attrType.getOrderingMatchingRule(schema);
    if (mrName != null)
    {
      return selectOrderingMatchingRule(mrName);
    }

    final String syntaxOID = attrType.getBaseSyntaxOID(schema);
    if (syntaxOID != null)
    {
      return selectMatchingRuleForSyntax(syntaxOID);
    }

    return getDefaultOrderingMatchingRule();
  }



  public static MatchingRule selectOrderingMatchingRule(final String ruleID)
  {
    if ((ruleID == null) || (ruleID.length() == 0))
    {
      return getDefaultOrderingMatchingRule();
    }

    final String lowerName = toLowerCase(ruleID);
    if (lowerName.equals(
             CaseExactStringMatchingRule.LOWER_ORDERING_RULE_NAME) ||
        lowerName.equals(CaseExactStringMatchingRule.ORDERING_RULE_OID))
    {
      return CaseExactStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  CaseIgnoreStringMatchingRule.LOWER_ORDERING_RULE_NAME) ||
             lowerName.equals(CaseIgnoreStringMatchingRule.ORDERING_RULE_OID))
    {
      return CaseIgnoreStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  GeneralizedTimeMatchingRule.LOWER_ORDERING_RULE_NAME) ||
             lowerName.equals(GeneralizedTimeMatchingRule.ORDERING_RULE_OID))
    {
      return GeneralizedTimeMatchingRule.getInstance();
    }
    else if (lowerName.equals(IntegerMatchingRule.LOWER_ORDERING_RULE_NAME) ||
             lowerName.equals(IntegerMatchingRule.ORDERING_RULE_OID))
    {
      return IntegerMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  NumericStringMatchingRule.LOWER_ORDERING_RULE_NAME) ||
             lowerName.equals(NumericStringMatchingRule.ORDERING_RULE_OID))
    {
      return NumericStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  OctetStringMatchingRule.LOWER_ORDERING_RULE_NAME) ||
             lowerName.equals(OctetStringMatchingRule.ORDERING_RULE_OID))
    {
      return OctetStringMatchingRule.getInstance();
    }
    else
    {
      return getDefaultOrderingMatchingRule();
    }
  }



  public static MatchingRule getDefaultOrderingMatchingRule()
  {
    return CaseIgnoreStringMatchingRule.getInstance();
  }


  public static MatchingRule selectSubstringMatchingRule(final String attrName,
                                                         final Schema schema)
  {
    return selectSubstringMatchingRule(attrName, null, schema);
  }



  public static MatchingRule selectSubstringMatchingRule(final String attrName,
                                                         final String ruleID,
                                                         final Schema schema)
  {
    if (ruleID != null)
    {
      return selectSubstringMatchingRule(ruleID);
    }

    if ((attrName == null) || (schema == null))
    {
      return getDefaultSubstringMatchingRule();
    }

    final AttributeTypeDefinition attrType = schema.getAttributeType(attrName);
    if (attrType == null)
    {
      return getDefaultSubstringMatchingRule();
    }

    final String mrName = attrType.getSubstringMatchingRule(schema);
    if (mrName != null)
    {
      return selectSubstringMatchingRule(mrName);
    }

    final String syntaxOID = attrType.getBaseSyntaxOID(schema);
    if (syntaxOID != null)
    {
      return selectMatchingRuleForSyntax(syntaxOID);
    }

    return getDefaultSubstringMatchingRule();
  }


  public static MatchingRule selectSubstringMatchingRule(final String ruleID)
  {
    if ((ruleID == null) || (ruleID.length() == 0))
    {
      return getDefaultSubstringMatchingRule();
    }

    final String lowerName = toLowerCase(ruleID);
    if (lowerName.equals(
             CaseExactStringMatchingRule.LOWER_SUBSTRING_RULE_NAME) ||
        lowerName.equals(CaseExactStringMatchingRule.SUBSTRING_RULE_OID) ||
        lowerName.equals("caseexactia5substringsmatch"))
    {
      return CaseExactStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  CaseIgnoreListMatchingRule.LOWER_SUBSTRING_RULE_NAME) ||
             lowerName.equals(CaseIgnoreListMatchingRule.SUBSTRING_RULE_OID))
    {
      return CaseIgnoreListMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  CaseIgnoreStringMatchingRule.LOWER_SUBSTRING_RULE_NAME) ||
             lowerName.equals(
                  CaseIgnoreStringMatchingRule.SUBSTRING_RULE_OID) ||
             lowerName.equals("caseignoreia5substringsmatch") ||
             lowerName.equals("1.3.6.1.4.1.1466.109.114.3"))
    {
      return CaseIgnoreStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  NumericStringMatchingRule.LOWER_SUBSTRING_RULE_NAME) ||
             lowerName.equals(NumericStringMatchingRule.SUBSTRING_RULE_OID))
    {
      return NumericStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  OctetStringMatchingRule.LOWER_SUBSTRING_RULE_NAME) ||
             lowerName.equals(OctetStringMatchingRule.SUBSTRING_RULE_OID))
    {
      return OctetStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  TelephoneNumberMatchingRule.LOWER_SUBSTRING_RULE_NAME) ||
             lowerName.equals(TelephoneNumberMatchingRule.SUBSTRING_RULE_OID))
    {
      return TelephoneNumberMatchingRule.getInstance();
    }
    else
    {
      return getDefaultSubstringMatchingRule();
    }
  }


  public static MatchingRule getDefaultSubstringMatchingRule()
  {
    return CaseIgnoreStringMatchingRule.getInstance();
  }



  public static MatchingRule selectMatchingRuleForSyntax(final String syntaxOID)
  {
    if (syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.7"))
    {
      return BooleanMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.41")) // Postal addr.
    {
      return CaseIgnoreListMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.12") ||
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.34")) // name&optional UID
    {
      return DistinguishedNameMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.24") ||
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.53")) // UTC time
    {
      return GeneralizedTimeMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.27"))
    {
      return IntegerMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.36"))
    {
      return NumericStringMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.4203.1.1.2") ||
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.5") ||
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.8") ||
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.9") ||
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.10") ||
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.28") ||
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.40"))
    {
      return OctetStringMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.50"))
    {
      return TelephoneNumberMatchingRule.getInstance();
    }
    else
    {
      return CaseIgnoreStringMatchingRule.getInstance();
    }
  }
}
