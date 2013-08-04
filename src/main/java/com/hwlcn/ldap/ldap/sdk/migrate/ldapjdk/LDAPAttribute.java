package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import java.io.Serializable;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Set;

import com.hwlcn.ldap.ldap.sdk.Attribute;
import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.StaticUtils.*;


@NotExtensible()
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public class LDAPAttribute
       implements Serializable
{

  private static final long serialVersionUID = 839217229050750570L;

  private Attribute attribute;

  public LDAPAttribute(final Attribute attr)
  {
    attribute = attr;
  }

  public LDAPAttribute(final LDAPAttribute attr)
  {
    attribute = attr.attribute;
  }


  public LDAPAttribute(final String attrName)
  {
    attribute = new Attribute(attrName);
  }


  public LDAPAttribute(final String attrName, final byte[] attrBytes)
  {
    attribute = new Attribute(attrName, attrBytes);
  }

  public LDAPAttribute(final String attrName, final String attrString)
  {
    attribute = new Attribute(attrName, attrString);
  }


  public LDAPAttribute(final String attrName, final String[] attrStrings)
  {
    attribute = new Attribute(attrName, attrStrings);
  }


  public String getName()
  {
    return attribute.getName();
  }


  public String getBaseName()
  {
    return attribute.getBaseName();
  }


  public static String getBaseName(final String attrName)
  {
    return Attribute.getBaseName(attrName);
  }

  public String[] getSubtypes()
  {
    final Set<String> optionSet = attribute.getOptions();
    if (optionSet.isEmpty())
    {
      return null;
    }

    final String[] options = new String[optionSet.size()];
    return optionSet.toArray(options);
  }

  public static String[] getSubtypes(final String attrName)
  {
    return new LDAPAttribute(attrName).getSubtypes();
  }

  public String getLangSubtype()
  {
    for (final String s : attribute.getOptions())
    {
      final String lowerName = toLowerCase(s);
      if (lowerName.startsWith("lang-"))
      {
        return s;
      }
    }

    return null;
  }


  public boolean hasSubtype(final String subtype)
  {
    return attribute.hasOption(subtype);
  }


  public boolean hasSubtypes(final String[] subtypes)
  {
    for (final String s : subtypes)
    {
      if (! attribute.hasOption(s))
      {
        return false;
      }
    }

    return true;
  }

  public Enumeration<String> getStringValues()
  {
    return new IterableEnumeration<String>(
         Arrays.asList(attribute.getValues()));
  }


  public String[] getStringValueArray()
  {
    return attribute.getValues();
  }


  public Enumeration<byte[]> getByteValues()
  {
    return new IterableEnumeration<byte[]>(
         Arrays.asList(attribute.getValueByteArrays()));
  }


  public byte[][] getByteValueArray()
  {
    return attribute.getValueByteArrays();
  }


  public void addValue(final String attrString)
  {
    attribute = Attribute.mergeAttributes(attribute,
         new Attribute(attribute.getName(), attrString));
  }



  public void addValue(final byte[] attrBytes)
  {
    attribute = Attribute.mergeAttributes(attribute,
         new Attribute(attribute.getName(), attrBytes));
  }


  public void removeValue(final String attrValue)
  {
    attribute = Attribute.removeValues(attribute,
         new Attribute(attribute.getName(), attrValue));
  }


  public void removeValue(final byte[] attrValue)
  {
    attribute = Attribute.removeValues(attribute,
         new Attribute(attribute.getName(), attrValue));
  }


  public int size()
  {
    return attribute.size();
  }



  public final Attribute toAttribute()
  {
    return attribute;
  }



  @Override()
  public String toString()
  {
    return attribute.toString();
  }
}
