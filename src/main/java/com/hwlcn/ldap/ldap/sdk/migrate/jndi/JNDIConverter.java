package com.hwlcn.ldap.ldap.sdk.migrate.jndi;



import java.util.Collection;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.BasicControl;
import javax.naming.ldap.ExtendedResponse;

import com.hwlcn.ldap.asn1.ASN1Exception;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.sdk.Attribute;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.Entry;
import com.hwlcn.ldap.ldap.sdk.ExtendedRequest;
import com.hwlcn.ldap.ldap.sdk.ExtendedResult;
import com.hwlcn.ldap.ldap.sdk.Modification;
import com.hwlcn.ldap.ldap.sdk.ModificationType;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.StaticUtils.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JNDIConverter
{
  private static final Attribute[] NO_ATTRIBUTES = new Attribute[0];

  private static final javax.naming.ldap.Control[] NO_JNDI_CONTROLS =
       new javax.naming.ldap.Control[0];

  private static final Modification[] NO_MODIFICATIONS = new Modification[0];

  private static final ModificationItem[] NO_MODIFICATION_ITEMS =
       new ModificationItem[0];

  private static final Control[] NO_SDK_CONTROLS = new Control[0];

  private JNDIConverter()
  {

  }

  public static Attribute convertAttribute(
                               final javax.naming.directory.Attribute a)
         throws NamingException
  {
    if (a == null)
    {
      return null;
    }

    final String name = a.getID();
    final ASN1OctetString[] values = new ASN1OctetString[a.size()];

    for (int i=0; i < values.length; i++)
    {
      final Object value = a.get(i);
      if (value instanceof byte[])
      {
        values[i] = new ASN1OctetString((byte[]) value);
      }
      else
      {
        values[i] = new ASN1OctetString(String.valueOf(value));
      }
    }

    return new Attribute(name, values);
  }


  public static javax.naming.directory.Attribute convertAttribute(
                                                      final Attribute a)
  {
    if (a == null)
    {
      return null;
    }

    final BasicAttribute attr = new BasicAttribute(a.getName(), true);
    for (final String v : a.getValues())
    {
      attr.add(v);
    }

    return attr;
  }


  public static Attribute[] convertAttributes(final Attributes a)
         throws NamingException
  {
    if (a == null)
    {
      return NO_ATTRIBUTES;
    }

    int i=0;
    final Attribute[] attributes = new Attribute[a.size()];
    final NamingEnumeration<? extends javax.naming.directory.Attribute> e =
         a.getAll();

    try
    {
      while (e.hasMoreElements())
      {
        attributes[i++] = convertAttribute(e.next());
      }
    }
    finally
    {
      e.close();
    }

    return attributes;
  }

  public static Attributes convertAttributes(final Attribute... a)
  {
    final BasicAttributes attrs = new BasicAttributes(true);
    if (a == null)
    {
      return attrs;
    }

    for (final Attribute attr : a)
    {
      attrs.put(convertAttribute(attr));
    }

    return attrs;
  }


  public static Attributes convertAttributes(final Collection<Attribute> a)
  {
    final BasicAttributes attrs = new BasicAttributes(true);
    if (a == null)
    {
      return attrs;
    }

    for (final Attribute attr : a)
    {
      attrs.put(convertAttribute(attr));
    }

    return attrs;
  }


  public static Control convertControl(final javax.naming.ldap.Control c)
         throws NamingException
  {
    if (c == null)
    {
      return null;
    }

    final ASN1OctetString value;
    final byte[] valueBytes = c.getEncodedValue();
    if ((valueBytes == null) || (valueBytes.length == 0))
    {
      value = null;
    }
    else
    {
      try
      {
        value = ASN1OctetString.decodeAsOctetString(valueBytes);
      }
      catch (ASN1Exception ae)
      {
        throw new NamingException(getExceptionMessage(ae));
      }
    }

    return new Control(c.getID(), c.isCritical(), value);
  }


  public static javax.naming.ldap.Control convertControl(final Control c)
  {
    if (c == null)
    {
      return null;
    }

    final ASN1OctetString value = c.getValue();
    if (value == null)
    {
      return new BasicControl(c.getOID(), c.isCritical(), null);
    }
    else
    {
      return new BasicControl(c.getOID(), c.isCritical(), value.encode());
    }
  }



  public static Control[] convertControls(final javax.naming.ldap.Control... c)
         throws NamingException
  {
    if (c == null)
    {
      return NO_SDK_CONTROLS;
    }

    final Control[] controls = new Control[c.length];
    for (int i=0; i < controls.length; i++)
    {
      controls[i] = convertControl(c[i]);
    }

    return controls;
  }


  public static javax.naming.ldap.Control[] convertControls(final Control... c)
  {
    if (c == null)
    {
      return NO_JNDI_CONTROLS;
    }

    final javax.naming.ldap.Control[] controls =
         new javax.naming.ldap.Control[c.length];
    for (int i=0; i < controls.length; i++)
    {
      controls[i] = convertControl(c[i]);
    }

    return controls;
  }


  public static ExtendedRequest convertExtendedRequest(
                                     final javax.naming.ldap.ExtendedRequest r)
         throws NamingException
  {
    if (r == null)
    {
      return null;
    }

    return JNDIExtendedRequest.toSDKExtendedRequest(r);
  }


  public static javax.naming.ldap.ExtendedRequest convertExtendedRequest(
                                                       final ExtendedRequest r)
  {
    if (r == null)
    {
      return null;
    }

    return new JNDIExtendedRequest(r);
  }


  public static ExtendedResult convertExtendedResponse(final ExtendedResponse r)
         throws NamingException
  {
    if (r == null)
    {
      return null;
    }

    return JNDIExtendedResponse.toSDKExtendedResult(r);
  }


  public static ExtendedResponse convertExtendedResult(final ExtendedResult r)
  {
    if (r == null)
    {
      return null;
    }

    return new JNDIExtendedResponse(r);
  }

  public static Modification convertModification(final ModificationItem m)
         throws NamingException
  {
    if (m == null)
    {
      return null;
    }

    final ModificationType modType;
    switch (m.getModificationOp())
    {
      case DirContext.ADD_ATTRIBUTE:
        modType = ModificationType.ADD;
        break;
      case DirContext.REMOVE_ATTRIBUTE:
        modType = ModificationType.DELETE;
        break;
      case DirContext.REPLACE_ATTRIBUTE:
        modType = ModificationType.REPLACE;
        break;
      default:
        throw new NamingException("Unsupported modification type " + m);
    }

    final Attribute a = convertAttribute(m.getAttribute());

    return new Modification(modType, a.getName(), a.getRawValues());
  }


  public static ModificationItem convertModification(final Modification m)
         throws NamingException
  {
    if (m == null)
    {
      return null;
    }

    final int modType;
    switch (m.getModificationType().intValue())
    {
      case ModificationType.ADD_INT_VALUE:
        modType = DirContext.ADD_ATTRIBUTE;
        break;
      case ModificationType.DELETE_INT_VALUE:
        modType = DirContext.REMOVE_ATTRIBUTE;
        break;
      case ModificationType.REPLACE_INT_VALUE:
        modType = DirContext.REPLACE_ATTRIBUTE;
        break;
      default:
        throw new NamingException("Unsupported modification type " + m);
    }

    return new ModificationItem(modType, convertAttribute(m.getAttribute()));
  }


  public static Modification[] convertModifications(final ModificationItem... m)
         throws NamingException
  {
    if (m == null)
    {
      return NO_MODIFICATIONS;
    }

    final Modification[] mods = new Modification[m.length];
    for (int i=0; i < m.length; i++)
    {
      mods[i] = convertModification(m[i]);
    }

    return mods;
  }



  public static ModificationItem[] convertModifications(final Modification... m)
         throws NamingException
  {
    if (m == null)
    {
      return NO_MODIFICATION_ITEMS;
    }

    final ModificationItem[] mods = new ModificationItem[m.length];
    for (int i=0; i < m.length; i++)
    {
      mods[i] = convertModification(m[i]);
    }

    return mods;
  }



  public static Entry convertSearchEntry(final SearchResult r)
         throws NamingException
  {
    if (r == null)
    {
      return null;
    }

    return new Entry(r.getName(), convertAttributes(r.getAttributes()));
  }



  public static SearchResult convertSearchEntry(final Entry e)
  {
    if (e == null)
    {
      return null;
    }

    final Collection<Attribute> attrs = e.getAttributes();
    final Attribute[] attributes = new Attribute[attrs.size()];
    attrs.toArray(attributes);

    return new SearchResult(e.getDN(), null, convertAttributes(attributes));
  }
}
