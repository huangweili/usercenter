package com.hwlcn.ldap.ldap.sdk.controls;



import java.util.ArrayList;
import java.util.Collection;

import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Exception;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.ldap.sdk.Attribute;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.DecodeableControl;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.LDAPResult;
import com.hwlcn.ldap.ldap.sdk.ReadOnlyEntry;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.controls.ControlMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.Validator.*;

@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PostReadResponseControl
       extends Control
       implements DecodeableControl
{

  public static final String POST_READ_RESPONSE_OID = "1.3.6.1.1.13.2";

  private static final long serialVersionUID = -6918729231330354924L;

  private final ReadOnlyEntry entry;

  PostReadResponseControl()
  {
    entry = null;
  }

  public PostReadResponseControl(final ReadOnlyEntry entry)
  {
    super(POST_READ_RESPONSE_OID, false, encodeValue(entry));

    this.entry = entry;
  }

  public PostReadResponseControl(final String oid, final boolean isCritical,
                                final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_POST_READ_RESPONSE_NO_VALUE.get());
    }

    final ASN1Sequence entrySequence;
    try
    {
      final ASN1Element entryElement = ASN1Element.decode(value.getValue());
      entrySequence = ASN1Sequence.decodeAsSequence(entryElement);
    }
    catch (final ASN1Exception ae)
    {
      debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_POST_READ_RESPONSE_VALUE_NOT_SEQUENCE.get(ae),
                              ae);
    }

    final ASN1Element[] entryElements = entrySequence.elements();
    if (entryElements.length != 2)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_POST_READ_RESPONSE_INVALID_ELEMENT_COUNT.get(
                                   entryElements.length));
    }

    final String dn =
         ASN1OctetString.decodeAsOctetString(entryElements[0]).stringValue();

    final ASN1Sequence attrSequence;
    try
    {
      attrSequence = ASN1Sequence.decodeAsSequence(entryElements[1]);
    }
    catch (final ASN1Exception ae)
    {
      debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                     ERR_POST_READ_RESPONSE_ATTRIBUTES_NOT_SEQUENCE.get(ae),
                     ae);
    }

    final ASN1Element[] attrElements = attrSequence.elements();
    final Attribute[] attrs = new Attribute[attrElements.length];
    for (int i=0; i < attrElements.length; i++)
    {
      try
      {
        attrs[i] =
             Attribute.decode(ASN1Sequence.decodeAsSequence(attrElements[i]));
      }
      catch (final ASN1Exception ae)
      {
        debugException(ae);
        throw new LDAPException(ResultCode.DECODING_ERROR,
                       ERR_POST_READ_RESPONSE_ATTR_NOT_SEQUENCE.get(ae), ae);
      }
    }

    entry = new ReadOnlyEntry(dn, attrs);
  }

  public PostReadResponseControl
              decodeControl(final String oid, final boolean isCritical,
                            final ASN1OctetString value)
         throws LDAPException
  {
    return new PostReadResponseControl(oid, isCritical, value);
  }

  public static PostReadResponseControl get(final LDAPResult result)
         throws LDAPException
  {
    final Control c = result.getResponseControl(POST_READ_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof PostReadResponseControl)
    {
      return (PostReadResponseControl) c;
    }
    else
    {
      return new PostReadResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }


  private static ASN1OctetString encodeValue(final ReadOnlyEntry entry)
  {
    ensureNotNull(entry);

    final Collection<Attribute> attrs = entry.getAttributes();
    final ArrayList<ASN1Element> attrElements =
         new ArrayList<ASN1Element>(attrs.size());
    for (final Attribute a : attrs)
    {
      attrElements.add(a.encode());
    }

    final ASN1Element[] entryElements =
    {
      new ASN1OctetString(entry.getDN()),
      new ASN1Sequence(attrElements)
    };

    return new ASN1OctetString(new ASN1Sequence(entryElements).encode());
  }


  public ReadOnlyEntry getEntry()
  {
    return entry;
  }

  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_POST_READ_RESPONSE.get();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("PostReadResponseControl(entry=");
    entry.toString(buffer);
    buffer.append(", isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
