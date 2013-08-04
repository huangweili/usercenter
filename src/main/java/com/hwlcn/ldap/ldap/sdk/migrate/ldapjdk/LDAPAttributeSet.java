package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;

import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.StaticUtils.*;

@NotExtensible()
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public class LDAPAttributeSet
       implements Serializable
{

  private static final long serialVersionUID = -4872457565092606186L;

  private final ArrayList<LDAPAttribute> attributes;

  public LDAPAttributeSet()
  {
    attributes = new ArrayList<LDAPAttribute>();
  }

  public LDAPAttributeSet(final LDAPAttribute[] attrs)
  {
    attributes = new ArrayList<LDAPAttribute>(Arrays.asList(attrs));
  }

  private LDAPAttributeSet(final ArrayList<LDAPAttribute> attrs)
  {
    attributes = new ArrayList<LDAPAttribute>(attrs);
  }

  public Enumeration<LDAPAttribute> getAttributes()
  {
    return new IterableEnumeration<LDAPAttribute>(attributes);
  }

  public LDAPAttributeSet getSubset(final String subtype)
  {
    final ArrayList<LDAPAttribute> subset =
         new ArrayList<LDAPAttribute>(attributes.size());

    for (final LDAPAttribute a : attributes)
    {
      if (a.hasSubtype(subtype))
      {
        subset.add(a);
      }
    }

    return new LDAPAttributeSet(subset);
  }

  public LDAPAttribute getAttribute(final String attrName)
  {
    for (final LDAPAttribute a : attributes)
    {
      if (a.getName().equalsIgnoreCase(attrName))
      {
        return a;
      }
    }

    return null;
  }

  public LDAPAttribute getAttribute(final String attrName, final String lang)
  {
    if (lang == null)
    {
      return getAttribute(attrName);
    }

    final String lowerLang = toLowerCase(lang);

    for (final LDAPAttribute a : attributes)
    {
      if (a.getBaseName().equalsIgnoreCase(attrName))
      {
        final String[] subtypes = a.getSubtypes();
        if (subtypes != null)
        {
          for (final String s : subtypes)
          {
            final String lowerOption = toLowerCase(s);
            if (lowerOption.equals(lowerLang) ||
                lowerOption.startsWith(lang + '-'))
            {
              return a;
            }
          }
        }
      }
    }

    return null;
  }

  public LDAPAttribute elementAt(final int index)
         throws IndexOutOfBoundsException
  {
    return attributes.get(index);
  }

  public void add(final LDAPAttribute attr)
  {
    for (final LDAPAttribute a : attributes)
    {
      if (attr.getName().equalsIgnoreCase(a.getName()))
      {
        for (final byte[] value : attr.getByteValueArray())
        {
          a.addValue(value);
        }
        return;
      }
    }

    attributes.add(attr);
  }


  public void remove(final String name)
  {
    final Iterator<LDAPAttribute> iterator = attributes.iterator();
    while (iterator.hasNext())
    {
      final LDAPAttribute a = iterator.next();
      if (name.equalsIgnoreCase(a.getName()))
      {
        iterator.remove();
        return;
      }
    }
  }


  public void removeElementAt(final int index)
         throws IndexOutOfBoundsException
  {
    attributes.remove(index);
  }


  public int size()
  {
    return attributes.size();
  }

  public LDAPAttributeSet duplicate()
  {
    return new LDAPAttributeSet(attributes);
  }

  @Override()
  public String toString()
  {
    return attributes.toString();
  }
}
