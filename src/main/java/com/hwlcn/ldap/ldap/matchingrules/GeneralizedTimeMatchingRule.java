package com.hwlcn.ldap.ldap.matchingrules;



import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.matchingrules.MatchingRuleMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;


@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GeneralizedTimeMatchingRule
       extends MatchingRule
{

  private static final GeneralizedTimeMatchingRule INSTANCE =
       new GeneralizedTimeMatchingRule();


  private static final String GENERALIZED_TIME_DATE_FORMAT =
       "yyyyMMddHHmmss.SSS'Z'";


  private static final TimeZone UTC_TIME_ZONE = TimeZone.getTimeZone("UTC");



  public static final String EQUALITY_RULE_NAME = "generalizedTimeMatch";



  static final String LOWER_EQUALITY_RULE_NAME =
       toLowerCase(EQUALITY_RULE_NAME);


  public static final String EQUALITY_RULE_OID = "2.5.13.27";


  public static final String ORDERING_RULE_NAME =
       "generalizedTimeOrderingMatch";



  static final String LOWER_ORDERING_RULE_NAME =
       toLowerCase(ORDERING_RULE_NAME);



  public static final String ORDERING_RULE_OID = "2.5.13.28";


  private static final long serialVersionUID = -6317451154598148593L;



  private static final ThreadLocal<SimpleDateFormat> dateFormat =
       new ThreadLocal<SimpleDateFormat>();


  public GeneralizedTimeMatchingRule()
  {
  }


  public static GeneralizedTimeMatchingRule getInstance()
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
    final Date d1;
    try
    {
      d1 = decodeGeneralizedTime(value1.stringValue());
    }
    catch (ParseException pe)
    {
      debugException(pe);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_GENERALIZED_TIME_INVALID_VALUE.get(pe.getMessage()), pe);
    }

    final Date d2;
    try
    {
      d2 = decodeGeneralizedTime(value2.stringValue());
    }
    catch (ParseException pe)
    {
      debugException(pe);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_GENERALIZED_TIME_INVALID_VALUE.get(pe.getMessage()), pe);
    }

    return d1.equals(d2);
  }



  @Override()
  public boolean matchesSubstring(final ASN1OctetString value,
                                  final ASN1OctetString subInitial,
                                  final ASN1OctetString[] subAny,
                                  final ASN1OctetString subFinal)
         throws LDAPException
  {
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
         ERR_GENERALIZED_TIME_SUBSTRING_MATCHING_NOT_SUPPORTED.get());
  }


  @Override()
  public int compareValues(final ASN1OctetString value1,
                           final ASN1OctetString value2)
         throws LDAPException
  {
    final Date d1;
    try
    {
      d1 = decodeGeneralizedTime(value1.stringValue());
    }
    catch (ParseException pe)
    {
      debugException(pe);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_GENERALIZED_TIME_INVALID_VALUE.get(pe.getMessage()), pe);
    }

    final Date d2;
    try
    {
      d2 = decodeGeneralizedTime(value2.stringValue());
    }
    catch (ParseException pe)
    {
      debugException(pe);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_GENERALIZED_TIME_INVALID_VALUE.get(pe.getMessage()), pe);
    }

    return d1.compareTo(d2);
  }

  @Override()
  public ASN1OctetString normalize(final ASN1OctetString value)
         throws LDAPException
  {
    final Date d;
    try
    {
      d = decodeGeneralizedTime(value.stringValue());
    }
    catch (ParseException pe)
    {
      debugException(pe);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_GENERALIZED_TIME_INVALID_VALUE.get(pe.getMessage()), pe);
    }

    SimpleDateFormat f = dateFormat.get();
    if (f == null)
    {
      f = new SimpleDateFormat(GENERALIZED_TIME_DATE_FORMAT);
      f.setTimeZone(UTC_TIME_ZONE);
      dateFormat.set(f);
    }

    return new ASN1OctetString(f.format(d));
  }


  @Override()
  public ASN1OctetString normalizeSubstring(final ASN1OctetString value,
                                            final byte substringType)
         throws LDAPException
  {
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
         ERR_GENERALIZED_TIME_SUBSTRING_MATCHING_NOT_SUPPORTED.get());
  }
}
