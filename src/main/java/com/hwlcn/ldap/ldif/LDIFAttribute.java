package com.hwlcn.ldap.ldif;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedHashSet;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.matchingrules.MatchingRule;
import com.hwlcn.ldap.ldap.sdk.Attribute;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
class LDIFAttribute
      implements Serializable
{

  private static final long serialVersionUID = -3771917482408643188L;

  private LinkedHashSet<ASN1OctetString> normalizedValues;

  private final ArrayList<ASN1OctetString> values;

  private final MatchingRule matchingRule;

  private final String name;

  LDIFAttribute(final String name, final MatchingRule matchingRule,
                final ASN1OctetString value)
  {
    this.name         = name;
    this.matchingRule = matchingRule;

    values = new ArrayList<ASN1OctetString>(5);
    values.add(value);

    normalizedValues = null;
  }


  boolean addValue(final ASN1OctetString value,
                   final DuplicateValueBehavior duplicateValueBehavior)
          throws LDAPException
  {
    if (normalizedValues == null)
    {
      normalizedValues = new LinkedHashSet<ASN1OctetString>();
      for (final ASN1OctetString s : values)
      {
        normalizedValues.add(matchingRule.normalize(s));
      }
    }

    if (normalizedValues.add(matchingRule.normalize(value)))
    {
      values.add(value);
      return true;
    }
    else
    {
      if (duplicateValueBehavior == DuplicateValueBehavior.RETAIN)
      {
        values.add(value);
        return true;
      }
      else
      {
        return false;
      }
    }
  }

  Attribute toAttribute()
  {
    final ASN1OctetString[] valueArray = new ASN1OctetString[values.size()];
    values.toArray(valueArray);

    return new Attribute(name, matchingRule, valueArray);
  }
}
