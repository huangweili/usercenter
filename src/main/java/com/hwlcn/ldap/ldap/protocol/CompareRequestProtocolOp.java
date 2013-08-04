
package com.hwlcn.ldap.ldap.protocol;



import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1BufferSequence;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.ldap.sdk.CompareRequest;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.protocol.ProtocolMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;


@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CompareRequestProtocolOp
       implements ProtocolOp
{

  private static final long serialVersionUID = -562642367801440060L;



  private final ASN1OctetString assertionValue;

  private final String attributeName;

  private final String dn;



  public CompareRequestProtocolOp(final String dn, final String attributeName,
                                  final ASN1OctetString assertionValue)
  {
    this.dn             = dn;
    this.attributeName  = attributeName;
    this.assertionValue = assertionValue;
  }


  public CompareRequestProtocolOp(final CompareRequest request)
  {
    dn             = request.getDN();
    attributeName  = request.getAttributeName();
    assertionValue = request.getRawAssertionValue();
  }



  CompareRequestProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      reader.beginSequence();
      dn = reader.readString();

      reader.beginSequence();
      attributeName = reader.readString();
      assertionValue = new ASN1OctetString(reader.readBytes());
      ensureNotNull(dn, attributeName, assertionValue);
    }
    catch (Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_COMPARE_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }



  public String getDN()
  {
    return dn;
  }



  public String getAttributeName()
  {
    return attributeName;
  }




  public ASN1OctetString getAssertionValue()
  {
    return assertionValue;
  }



  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST;
  }



  public ASN1Element encodeProtocolOp()
  {
    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
         new ASN1OctetString(dn),
         new ASN1Sequence(
              new ASN1OctetString(attributeName),
              assertionValue));
  }


  public static CompareRequestProtocolOp decodeProtocolOp(
                                              final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final String dn =
           ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

      final ASN1Element[] avaElements =
           ASN1Sequence.decodeAsSequence(elements[1]).elements();
      final String attributeName =
           ASN1OctetString.decodeAsOctetString(avaElements[0]).stringValue();
      final ASN1OctetString assertionValue =
           ASN1OctetString.decodeAsOctetString(avaElements[1]);

      return new CompareRequestProtocolOp(dn, attributeName, assertionValue);
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_COMPARE_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)),
           e);
    }
  }



  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST);
    buffer.addOctetString(dn);

    final ASN1BufferSequence avaSequence = buffer.beginSequence();
    buffer.addOctetString(attributeName);
    buffer.addElement(assertionValue);
    avaSequence.end();
    opSequence.end();
  }



  public CompareRequest toCompareRequest(final Control... controls)
  {
    return new CompareRequest(dn, attributeName, assertionValue.getValue(),
         controls);
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
    buffer.append("CompareRequestProtocolOp(dn='");
    buffer.append(dn);
    buffer.append("', attributeName='");
    buffer.append(attributeName);
    buffer.append("', assertionValue='");
    buffer.append(assertionValue.stringValue());
    buffer.append("')");
  }
}
