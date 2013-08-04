package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Enumeration;

import com.hwlcn.ldap.ldap.sdk.Attribute;
import com.hwlcn.ldap.ldap.sdk.Entry;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public class LDAPEntry
       implements Serializable
{
  private static final long serialVersionUID = -6285850560316222689L;


  private final String dn;

  private final LDAPAttributeSet attributeSet;


  public LDAPEntry()
  {
    this("", new LDAPAttributeSet());
  }



  public LDAPEntry(final String distinguishedName)
  {
    this(distinguishedName, new LDAPAttributeSet());
  }


  public LDAPEntry(final String distinguishedName, final LDAPAttributeSet attrs)
  {
    dn = distinguishedName;

    if (attrs == null)
    {
      attributeSet = new LDAPAttributeSet();
    }
    else
    {
      attributeSet = attrs;
    }
  }

  public LDAPEntry(final Entry entry)
  {
    dn = entry.getDN();

    attributeSet = new LDAPAttributeSet();
    for (final Attribute a : entry.getAttributes())
    {
      attributeSet.add(new LDAPAttribute(a));
    }
  }


  public String getDN()
  {
    return dn;
  }


  public LDAPAttributeSet getAttributeSet()
  {
    return attributeSet;
  }


  public LDAPAttributeSet getAttributeSet(final String subtype)
  {
    return attributeSet.getSubset(subtype);
  }

  public LDAPAttribute getAttribute(final String attrName)
  {
    return attributeSet.getAttribute(attrName);
  }


  public LDAPAttribute getAttribute(final String attrName, final String lang)
  {
    return attributeSet.getAttribute(attrName, lang);
  }


  public final Entry toEntry()
  {
    final ArrayList<Attribute> attrs =
         new ArrayList<Attribute>(attributeSet.size());
    final Enumeration<LDAPAttribute> attrEnum = attributeSet.getAttributes();
    while (attrEnum.hasMoreElements())
    {
      attrs.add(attrEnum.nextElement().toAttribute());
    }

    return new Entry(dn, attrs);
  }


  @Override()
  public String toString()
  {
    return toEntry().toString();
  }
}
