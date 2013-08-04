package com.hwlcn.ldap.ldap.sdk.controls;



import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Enumerated;
import com.hwlcn.ldap.asn1.ASN1Exception;
import com.hwlcn.ldap.asn1.ASN1Integer;
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
public final class VirtualListViewResponseControl
       extends Control
       implements DecodeableControl
{

  public static final String VIRTUAL_LIST_VIEW_RESPONSE_OID =
       "2.16.840.1.113730.3.4.10";

  private static final long serialVersionUID = -534656674756287217L;

 private final ASN1OctetString contextID;

 private final int contentCount;
  private final ResultCode resultCode;
 private final int targetPosition;


  VirtualListViewResponseControl()
  {
    targetPosition = -1;
    contentCount   = -1;
    resultCode     = null;
    contextID      = null;
  }


  public VirtualListViewResponseControl(final int targetPosition,
              final int contentCount, final ResultCode resultCode,
              final ASN1OctetString contextID)
  {
    super(VIRTUAL_LIST_VIEW_RESPONSE_OID, false,
          encodeValue(targetPosition, contentCount, resultCode, contextID));

    this.targetPosition = targetPosition;
    this.contentCount   = contentCount;
    this.resultCode     = resultCode;
    this.contextID      = contextID;
  }


  public VirtualListViewResponseControl(final String oid,
                                        final boolean isCritical,
                                        final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_VLV_RESPONSE_NO_VALUE.get());
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
                              ERR_VLV_RESPONSE_VALUE_NOT_SEQUENCE.get(ae), ae);
    }

    final ASN1Element[] valueElements = valueSequence.elements();
    if ((valueElements.length < 3) || (valueElements.length > 4))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_VLV_RESPONSE_INVALID_ELEMENT_COUNT.get(
                                   valueElements.length));
    }

    try
    {
      targetPosition = ASN1Integer.decodeAsInteger(valueElements[0]).intValue();
    }
    catch (final ASN1Exception ae)
    {
      debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_VLV_RESPONSE_FIRST_NOT_INTEGER.get(ae), ae);
    }

    try
    {
      contentCount = ASN1Integer.decodeAsInteger(valueElements[1]).intValue();
    }
    catch (final ASN1Exception ae)
    {
      debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_VLV_RESPONSE_SECOND_NOT_INTEGER.get(ae), ae);
    }

    try
    {
      final int rc =
           ASN1Enumerated.decodeAsEnumerated(valueElements[2]).intValue();
      resultCode = ResultCode.valueOf(rc);
    }
    catch (final ASN1Exception ae)
    {
      debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_VLV_RESPONSE_THIRD_NOT_ENUM.get(ae), ae);
    }

    if (valueElements.length == 4)
    {
      contextID = ASN1OctetString.decodeAsOctetString(valueElements[3]);
    }
    else
    {
      contextID = null;
    }
  }


  public VirtualListViewResponseControl
              decodeControl(final String oid, final boolean isCritical,
                            final ASN1OctetString value)
         throws LDAPException
  {
    return new VirtualListViewResponseControl(oid, isCritical, value);
  }


  public static VirtualListViewResponseControl get(final SearchResult result)
         throws LDAPException
  {
    final Control c = result.getResponseControl(VIRTUAL_LIST_VIEW_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof VirtualListViewResponseControl)
    {
      return (VirtualListViewResponseControl) c;
    }
    else
    {
      return new VirtualListViewResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }


  private static ASN1OctetString encodeValue(final int targetPosition,
                                             final int contentCount,
                                             final ResultCode resultCode,
                                             final ASN1OctetString contextID)
  {
    final ASN1Element[] vlvElements;
    if (contextID == null)
    {
      vlvElements = new ASN1Element[]
      {
        new ASN1Integer(targetPosition),
        new ASN1Integer(contentCount),
        new ASN1Enumerated(resultCode.intValue())
      };
    }
    else
    {
      vlvElements = new ASN1Element[]
      {
        new ASN1Integer(targetPosition),
        new ASN1Integer(contentCount),
        new ASN1Enumerated(resultCode.intValue()),
        contextID
      };
    }

    return new ASN1OctetString(new ASN1Sequence(vlvElements).encode());
  }


  public int getTargetPosition()
  {
    return targetPosition;
  }

  public int getContentCount()
  {
    return contentCount;
  }

  public ResultCode getResultCode()
  {
    return resultCode;
  }

  public ASN1OctetString getContextID()
  {
    return contextID;
  }


  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_VLV_RESPONSE.get();
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("VirtualListViewResponseControl(targetPosition=");
    buffer.append(targetPosition);
    buffer.append(", contentCount=");
    buffer.append(contentCount);
    buffer.append(", resultCode=");
    buffer.append(resultCode);
    buffer.append(')');
  }
}
