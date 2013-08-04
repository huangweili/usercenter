package com.hwlcn.ldap.ldap.protocol;



import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Integer;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
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
public final class AbandonRequestProtocolOp
       implements ProtocolOp
{

  private static final long serialVersionUID = -7824390696388231825L;


  private final int idToAbandon;




  public AbandonRequestProtocolOp(final int idToAbandon)
  {
    this.idToAbandon = idToAbandon;
  }




  AbandonRequestProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      idToAbandon = reader.readInteger();
    }
    catch (Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ABANDON_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }



  public int getIDToAbandon()
  {
    return idToAbandon;
  }



  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST;
  }



  public ASN1Element encodeProtocolOp()
  {
    return new ASN1Integer(LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
         idToAbandon);
  }



  public static AbandonRequestProtocolOp decodeProtocolOp(
                                              final ASN1Element element)
         throws LDAPException
  {
    try
    {
      return new AbandonRequestProtocolOp(
           ASN1Integer.decodeAsInteger(element).intValue());
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ABANDON_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)),
           e);
    }
  }



  public void writeTo(final ASN1Buffer buffer)
  {
    buffer.addInteger(LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
                      idToAbandon);
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
    buffer.append("AbandonRequestProtocolOp(idToAbandon=");
    buffer.append(idToAbandon);
    buffer.append(')');
  }
}
