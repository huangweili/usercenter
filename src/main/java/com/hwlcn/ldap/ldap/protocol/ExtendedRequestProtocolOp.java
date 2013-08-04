
package com.hwlcn.ldap.ldap.protocol;



import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1BufferSequence;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.ExtendedRequest;
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
public final class ExtendedRequestProtocolOp
       implements ProtocolOp
{

  public static final byte TYPE_OID = (byte) 0x80;


  public static final byte TYPE_VALUE = (byte) 0x81;



  private static final long serialVersionUID = -5343424210200494377L;



  private final ASN1OctetString value;

  private final String oid;



  public ExtendedRequestProtocolOp(final String oid,
                                   final ASN1OctetString value)
  {
    this.oid = oid;

    if (value == null)
    {
      this.value = null;
    }
    else
    {
      this.value = new ASN1OctetString(TYPE_VALUE, value.getValue());
    }
  }



  public ExtendedRequestProtocolOp(final ExtendedRequest request)
  {
    oid   = request.getOID();
    value = request.getValue();
  }




  ExtendedRequestProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      final ASN1StreamReaderSequence opSequence = reader.beginSequence();
      oid = reader.readString();
      ensureNotNull(oid);

      if (opSequence.hasMoreElements())
      {
        value = new ASN1OctetString(TYPE_VALUE, reader.readBytes());
      }
      else
      {
        value = null;
      }
    }
    catch (Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_EXTENDED_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }



  public String getOID()
  {
    return oid;
  }


  public ASN1OctetString getValue()
  {
    return value;
  }



  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST;
  }


  public ASN1Element encodeProtocolOp()
  {
    if (value ==  null)
    {
      return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
           new ASN1OctetString(TYPE_OID, oid));
    }
    else
    {
      return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
           new ASN1OctetString(TYPE_OID, oid),
           value);
    }
  }


  public static ExtendedRequestProtocolOp decodeProtocolOp(
                                               final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final String oid =
           ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

      final ASN1OctetString value;
      if (elements.length == 1)
      {
        value = null;
      }
      else
      {
        value = ASN1OctetString.decodeAsOctetString(elements[1]);
      }

      return new ExtendedRequestProtocolOp(oid, value);
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_EXTENDED_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)),
           e);
    }
  }



  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST);
    buffer.addOctetString(TYPE_OID, oid);

    if (value != null)
    {
      buffer.addOctetString(TYPE_VALUE, value.getValue());
    }
    opSequence.end();
  }




  public ExtendedRequest toExtendedRequest(final Control... controls)
  {
    return new ExtendedRequest(oid, value, controls);
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
    buffer.append("ExtendedRequestProtocolOp(oid='");
    buffer.append(oid);
    buffer.append("')");
  }
}
