
package com.hwlcn.ldap.ldap.sdk.controls;



import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Enumerated;
import com.hwlcn.ldap.asn1.ASN1Exception;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.DecodeableControl;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.ldap.ldap.sdk.SearchResult;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.controls.ControlMessages.*;
import static com.hwlcn.ldap.util.Debug.*;



@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ServerSideSortResponseControl
       extends Control
       implements DecodeableControl
{
 public static final String SERVER_SIDE_SORT_RESPONSE_OID =
       "1.2.840.113556.1.4.474";

  private static final byte TYPE_ATTRIBUTE_TYPE = (byte) 0x80;

  private static final long serialVersionUID = -8707533262822875822L;

  private final ResultCode resultCode;

  private final String attributeName;

  ServerSideSortResponseControl()
  {
    resultCode    = null;
    attributeName = null;
  }


  public ServerSideSortResponseControl(final ResultCode resultCode,
                                       final String attributeName,
                                       final boolean isCritical)
  {
    super(SERVER_SIDE_SORT_RESPONSE_OID, isCritical,
          encodeValue(resultCode, attributeName));

    this.resultCode    = resultCode;
    this.attributeName = attributeName;
  }


  public ServerSideSortResponseControl(final String oid,
                                       final boolean isCritical,
                                       final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SORT_RESPONSE_NO_VALUE.get());
    }

    final ASN1Sequence valueSequence;
    try
    {
      final ASN1Element valueElement =
           ASN1Element.decode(value.getValue());
      valueSequence = ASN1Sequence.decodeAsSequence(valueElement);
    }
    catch (final ASN1Exception ae)
    {
      debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SORT_RESPONSE_VALUE_NOT_SEQUENCE.get(ae), ae);
    }

    final ASN1Element[] valueElements = valueSequence.elements();
    if ((valueElements.length < 1) || (valueElements.length > 2))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SORT_RESPONSE_INVALID_ELEMENT_COUNT.get(
                                   valueElements.length));
    }

    try
    {
      final int rc =
           ASN1Enumerated.decodeAsEnumerated(valueElements[0]).intValue();
      resultCode = ResultCode.valueOf(rc);
    }
    catch (final ASN1Exception ae)
    {
      debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SORT_RESPONSE_FIRST_NOT_ENUM.get(ae), ae);
    }

    if (valueElements.length == 2)
    {
      attributeName =
           ASN1OctetString.decodeAsOctetString(valueElements[1]).stringValue();
    }
    else
    {
      attributeName = null;
    }
  }

  public ServerSideSortResponseControl
              decodeControl(final String oid, final boolean isCritical,
                            final ASN1OctetString value)
         throws LDAPException
  {
    return new ServerSideSortResponseControl(oid, isCritical, value);
  }

  public static ServerSideSortResponseControl get(final SearchResult result)
         throws LDAPException
  {
    final Control c = result.getResponseControl(SERVER_SIDE_SORT_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof ServerSideSortResponseControl)
    {
      return (ServerSideSortResponseControl) c;
    }
    else
    {
      return new ServerSideSortResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }


  private static ASN1OctetString encodeValue(final ResultCode resultCode,
                                             final String attributeName)
  {
    final ASN1Element[] valueElements;
    if (attributeName == null)
    {
      valueElements = new ASN1Element[]
      {
        new ASN1Enumerated(resultCode.intValue())
      };
    }
    else
    {
      valueElements = new ASN1Element[]
      {
        new ASN1Enumerated(resultCode.intValue()),
        new ASN1OctetString(TYPE_ATTRIBUTE_TYPE, attributeName)
      };
    }

    return new ASN1OctetString(new ASN1Sequence(valueElements).encode());
  }


  public ResultCode getResultCode()
  {
    return resultCode;
  }

  public String getAttributeName()
  {
    return attributeName;
  }

  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_SORT_RESPONSE.get();
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ServerSideSortResponseControl(resultCode=");
    buffer.append(resultCode);

    if (attributeName != null)
    {
      buffer.append(", attributeName='");
      buffer.append(attributeName);
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
