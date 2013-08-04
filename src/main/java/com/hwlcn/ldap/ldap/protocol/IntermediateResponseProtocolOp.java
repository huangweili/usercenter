
package com.hwlcn.ldap.ldap.protocol;



import java.util.ArrayList;

import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1BufferSequence;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.IntermediateResponse;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ResultCode;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.protocol.ProtocolMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;



@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class IntermediateResponseProtocolOp
       implements ProtocolOp
{

  public static final byte TYPE_OID = (byte) 0x80;



  public static final byte TYPE_VALUE = (byte) 0x81;

  private static final long serialVersionUID = 118549806265654465L;

  private final ASN1OctetString value;

  private final String oid;

  public IntermediateResponseProtocolOp(final String oid,
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

  public IntermediateResponseProtocolOp(final IntermediateResponse response)
  {
    oid   = response.getOID();
    value = response.getValue();
  }

  IntermediateResponseProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      final ASN1StreamReaderSequence opSequence = reader.beginSequence();

      String o = null;
      ASN1OctetString v = null;
      while (opSequence.hasMoreElements())
      {
        final byte type = (byte) reader.peek();
        if (type == TYPE_OID)
        {
          o = reader.readString();
        }
        else if (type == TYPE_VALUE)
        {
          v = new ASN1OctetString(type, reader.readBytes());
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_INTERMEDIATE_RESPONSE_INVALID_ELEMENT.get(toHex(type)));
        }
      }

      oid = o;
      value = v;
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw le;
    }
    catch (Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_INTERMEDIATE_RESPONSE_CANNOT_DECODE.get(getExceptionMessage(e)),
           e);
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
    return LDAPMessage.PROTOCOL_OP_TYPE_INTERMEDIATE_RESPONSE;
  }

  public ASN1Element encodeProtocolOp()
  {
    final ArrayList<ASN1Element> elements = new ArrayList<ASN1Element>(2);

    if (oid != null)
    {
      elements.add(new ASN1OctetString(TYPE_OID, oid));
    }

    if (value != null)
    {
      elements.add(value);
    }

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_INTERMEDIATE_RESPONSE,
         elements);
  }

  public static IntermediateResponseProtocolOp decodeProtocolOp(
                                                    final ASN1Element element)
         throws LDAPException
  {
    try
    {
      String oid = null;
      ASN1OctetString value = null;
      for (final ASN1Element e :
           ASN1Sequence.decodeAsSequence(element).elements())
      {
        switch (e.getType())
        {
          case TYPE_OID:
            oid = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_VALUE:
            value = ASN1OctetString.decodeAsOctetString(e);
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_INTERMEDIATE_RESPONSE_INVALID_ELEMENT.get(
                      toHex(e.getType())));
        }
      }

      return new IntermediateResponseProtocolOp(oid, value);
    }
    catch (final LDAPException le)
    {
      debugException(le);
      throw le;
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
    final ASN1BufferSequence opSequence = buffer.beginSequence(
         LDAPMessage.PROTOCOL_OP_TYPE_INTERMEDIATE_RESPONSE);

    if (oid != null)
    {
      buffer.addOctetString(TYPE_OID, oid);
    }

    if (value != null)
    {
      buffer.addElement(value);
    }

    opSequence.end();
  }

  public IntermediateResponse toIntermediateResponse(final Control... controls)
  {
    return new IntermediateResponse(-1, oid, value, controls);
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
    buffer.append("IntermediateResponseProtocolOp(");

    if (oid != null)
    {
      buffer.append("oid='");
      buffer.append(oid);
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
