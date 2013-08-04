
package com.hwlcn.ldap.ldap.sdk.controls;



import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.controls.ControlMessages.*;
import static com.hwlcn.ldap.util.Debug.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PreReadRequestControl
       extends Control
{

  public static final String PRE_READ_REQUEST_OID = "1.3.6.1.1.13.1";


  private static final String[] NO_ATTRIBUTES = StaticUtils.NO_STRINGS;


  private static final long serialVersionUID = 1205235290978028739L;

  private final String[] attributes;

  public PreReadRequestControl(final String... attributes)
  {
    this(true, attributes);
  }

  public PreReadRequestControl(final boolean isCritical,
                               final String... attributes)
  {
    super(PRE_READ_REQUEST_OID, isCritical, encodeValue(attributes));

    if (attributes == null)
    {
      this.attributes = NO_ATTRIBUTES;
    }
    else
    {
      this.attributes = attributes;
    }
  }


  public PreReadRequestControl(final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PRE_READ_REQUEST_NO_VALUE.get());
    }

    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      final ASN1Element[] attrElements =
           ASN1Sequence.decodeAsSequence(valueElement).elements();
      attributes = new String[attrElements.length];
      for (int i=0; i < attrElements.length; i++)
      {
        attributes[i] =
             ASN1OctetString.decodeAsOctetString(attrElements[i]).stringValue();
      }
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PRE_READ_REQUEST_CANNOT_DECODE.get(e), e);
    }
  }


  private static ASN1OctetString encodeValue(final String[] attributes)
  {
    if ((attributes == null) || (attributes.length == 0))
    {
      return new ASN1OctetString(new ASN1Sequence().encode());
    }

    final ASN1OctetString[] elements = new ASN1OctetString[attributes.length];
    for (int i=0; i < attributes.length; i++)
    {
      elements[i] = new ASN1OctetString(attributes[i]);
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }

  public String[] getAttributes()
  {
    return attributes;
  }

  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PRE_READ_REQUEST.get();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("PreReadRequestControl(attributes={");
    for (int i=0; i < attributes.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }
      buffer.append('\'');
      buffer.append(attributes[i]);
      buffer.append('\'');
    }
    buffer.append("}, isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
