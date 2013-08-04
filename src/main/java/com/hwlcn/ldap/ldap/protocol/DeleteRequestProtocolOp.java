
package com.hwlcn.ldap.ldap.protocol;



import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.DeleteRequest;
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
public final class DeleteRequestProtocolOp
       implements ProtocolOp
{

  private static final long serialVersionUID = 1577020640104649789L;

  private final String dn;


  public DeleteRequestProtocolOp(final String dn)
  {
    this.dn = dn;
  }


  public DeleteRequestProtocolOp(final DeleteRequest request)
  {
    dn = request.getDN();
  }



  DeleteRequestProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      dn = reader.readString();
      ensureNotNull(dn);
    }
    catch (Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_DELETE_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }


  public String getDN()
  {
    return dn;
  }


  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST;
  }



  public ASN1Element encodeProtocolOp()
  {
    return new ASN1OctetString(LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST, dn);
  }



  public static DeleteRequestProtocolOp decodeProtocolOp(
                                             final ASN1Element element)
         throws LDAPException
  {
    try
    {
      return new DeleteRequestProtocolOp(
           ASN1OctetString.decodeAsOctetString(element).stringValue());
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_DELETE_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)),
           e);
    }
  }



  public void writeTo(final ASN1Buffer buffer)
  {
    buffer.addOctetString(LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST, dn);
  }

  public DeleteRequest toDeleteRequest(final Control... controls)
  {
    return new DeleteRequest(dn, controls);
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
    buffer.append("DeleteRequestProtocolOp(dn='");
    buffer.append(dn);
    buffer.append("')");
  }
}
