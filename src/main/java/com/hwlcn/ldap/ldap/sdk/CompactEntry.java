package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import com.hwlcn.ldap.util.ByteStringBuffer;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Validator.*;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class CompactEntry
       implements Serializable
{

  private static final long serialVersionUID = 8067151651120794058L;

  private final CompactAttribute[] attributes;

  private int hashCode;

  private final String dn;

  public CompactEntry(final Entry entry)
  {
    ensureNotNull(entry);

    dn = entry.getDN();
    hashCode = -1;

    final Collection<Attribute> attrs = entry.getAttributes();
    attributes = new CompactAttribute[attrs.size()];
    final Iterator<Attribute> iterator = attrs.iterator();
    for (int i=0; i < attributes.length; i++)
    {
      attributes[i] = new CompactAttribute(iterator.next());
    }
  }


  public String getDN()
  {
    return dn;
  }

  public DN getParsedDN()
         throws LDAPException
  {
    return new DN(dn);
  }



  public RDN getRDN()
         throws LDAPException
  {
    return getParsedDN().getRDN();
  }


  public DN getParentDN()
         throws LDAPException
  {
    return getParsedDN().getParent();
  }


  public String getParentDNString()
         throws LDAPException
  {
    return getParsedDN().getParentString();
  }

  public boolean hasAttribute(final String attributeName)
  {
    ensureNotNull(attributeName);

    for (final CompactAttribute a : attributes)
    {
      if (a.getName().equalsIgnoreCase(attributeName))
      {
        return true;
      }
    }

    return false;
  }


  public boolean hasAttribute(final Attribute attribute)
  {
    ensureNotNull(attribute);

    for (final CompactAttribute a : attributes)
    {
      if (a.toAttribute().equals(attribute))
      {
        return true;
      }
    }

    return false;
  }

  public boolean hasAttributeValue(final String attributeName,
                                   final String attributeValue)
  {
    ensureNotNull(attributeName, attributeValue);

    for (final CompactAttribute a : attributes)
    {
      if (a.getName().equalsIgnoreCase(attributeName) &&
          a.toAttribute().hasValue(attributeValue))
      {
        return true;
      }
    }

    return false;
  }

  public boolean hasAttributeValue(final String attributeName,
                                   final byte[] attributeValue)
  {
    ensureNotNull(attributeName, attributeValue);

    for (final CompactAttribute a : attributes)
    {
      if (a.getName().equalsIgnoreCase(attributeName) &&
          a.toAttribute().hasValue(attributeValue))
      {
        return true;
      }
    }

    return false;
  }

  public boolean hasObjectClass(final String objectClassName)
  {
    return hasAttributeValue("objectClass", objectClassName);
  }

  public Collection<Attribute> getAttributes()
  {
    final ArrayList<Attribute> attrList =
         new ArrayList<Attribute>(attributes.length);
    for (final CompactAttribute a : attributes)
    {
      attrList.add(a.toAttribute());
    }

    return Collections.unmodifiableCollection(attrList);
  }

  public Attribute getAttribute(final String attributeName)
  {
    ensureNotNull(attributeName);

    for (final CompactAttribute a : attributes)
    {
      if (a.getName().equalsIgnoreCase(attributeName))
      {
        return a.toAttribute();
      }
    }

    return null;
  }

  public List<Attribute> getAttributesWithOptions(final String baseName,
                                                  final Set<String> options)
  {
    return toEntry().getAttributesWithOptions(baseName, options);
  }

  public String getAttributeValue(final String attributeName)
  {
    ensureNotNull(attributeName);

    for (final CompactAttribute a : attributes)
    {
      if (a.getName().equalsIgnoreCase(attributeName))
      {
        final String[] values = a.getStringValues();
        if (values.length > 0)
        {
          return values[0];
        }
        else
        {
          return null;
        }
      }
    }

    return null;
  }

  public byte[] getAttributeValueBytes(final String attributeName)
  {
    ensureNotNull(attributeName);

    for (final CompactAttribute a : attributes)
    {
      if (a.getName().equalsIgnoreCase(attributeName))
      {
        final byte[][] values = a.getByteValues();
        if (values.length > 0)
        {
          return values[0];
        }
        else
        {
          return null;
        }
      }
    }

    return null;
  }


  public Boolean getAttributeValueAsBoolean(final String attributeName)
  {
    ensureNotNull(attributeName);

    final Attribute a = getAttribute(attributeName);
    if (a == null)
    {
      return null;
    }
    else
    {
      return a.getValueAsBoolean();
    }
  }

  public Date getAttributeValueAsDate(final String attributeName)
  {
    ensureNotNull(attributeName);

    final Attribute a = getAttribute(attributeName);
    if (a == null)
    {
      return null;
    }
    else
    {
      return a.getValueAsDate();
    }
  }

  public DN getAttributeValueAsDN(final String attributeName)
  {
    ensureNotNull(attributeName);

    final Attribute a = getAttribute(attributeName);
    if (a == null)
    {
      return null;
    }
    else
    {
      return a.getValueAsDN();
    }
  }


  public Integer getAttributeValueAsInteger(final String attributeName)
  {
    ensureNotNull(attributeName);

    final Attribute a = getAttribute(attributeName);
    if (a == null)
    {
      return null;
    }
    else
    {
      return a.getValueAsInteger();
    }
  }



  public Long getAttributeValueAsLong(final String attributeName)
  {
    ensureNotNull(attributeName);

    final Attribute a = getAttribute(attributeName);
    if (a == null)
    {
      return null;
    }
    else
    {
      return a.getValueAsLong();
    }
  }

  public String[] getAttributeValues(final String attributeName)
  {
    ensureNotNull(attributeName);

    for (final CompactAttribute a : attributes)
    {
      if (a.getName().equalsIgnoreCase(attributeName))
      {
        return a.getStringValues();
      }
    }

    return null;
  }

  public byte[][] getAttributeValueByteArrays(final String attributeName)
  {
    ensureNotNull(attributeName);

    for (final CompactAttribute a : attributes)
    {
      if (a.getName().equalsIgnoreCase(attributeName))
      {
        return a.getByteValues();
      }
    }

    return null;
  }


  public Attribute getObjectClassAttribute()
  {
    return getAttribute("objectClass");
  }

  public String[] getObjectClassValues()
  {
    return getAttributeValues("objectClass");
  }


  public Entry toEntry()
  {
    final Attribute[] attrs = new Attribute[attributes.length];
    for (int i=0; i < attributes.length; i++)
    {
      attrs[i] = attributes[i].toAttribute();
    }

    return new Entry(dn, attrs);
  }

  @Override()
  public int hashCode()
  {
    if (hashCode == -1)
    {
      hashCode = toEntry().hashCode();
    }

    return hashCode;
  }


  @Override()
  public boolean equals(final Object o)
  {
    if ((o == null) || (! (o instanceof CompactEntry)))
    {
      return false;
    }

    return toEntry().equals(((CompactEntry) o).toEntry());
  }

  public String[] toLDIF()
  {
    return toLDIF(0);
  }


  public String[] toLDIF(final int wrapColumn)
  {
    return toEntry().toLDIF(wrapColumn);
  }


  public void toLDIF(final ByteStringBuffer buffer)
  {
    toLDIF(buffer, 0);
  }

  public void toLDIF(final ByteStringBuffer buffer, final int wrapColumn)
  {
    toEntry().toLDIF(buffer, wrapColumn);
  }


  public String toLDIFString()
  {
    final StringBuilder buffer = new StringBuilder();
    toLDIFString(buffer, 0);
    return buffer.toString();
  }


  public String toLDIFString(final int wrapColumn)
  {
    final StringBuilder buffer = new StringBuilder();
    toLDIFString(buffer, wrapColumn);
    return buffer.toString();
  }


  public void toLDIFString(final StringBuilder buffer)
  {
    toLDIFString(buffer, 0);
  }


  public void toLDIFString(final StringBuilder buffer,
                                 final int wrapColumn)
  {
    toEntry().toLDIFString(buffer, wrapColumn);
  }

  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }

  public void toString(final StringBuilder buffer)
  {
    buffer.append("Entry(dn='");
    buffer.append(dn);
    buffer.append("', attributes={");

    for (int i=0; i < attributes.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }
      attributes[i].toAttribute().toString(buffer);
    }

    buffer.append("})");
  }
}
