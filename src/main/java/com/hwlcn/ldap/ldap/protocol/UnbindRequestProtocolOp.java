
package com.hwlcn.ldap.ldap.protocol;



import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1Null;
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
public final class UnbindRequestProtocolOp
       implements ProtocolOp
{

  private static final long serialVersionUID = 1703200292192488474L;



  public UnbindRequestProtocolOp()
  {
  }


  UnbindRequestProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      reader.readNull();
    }
    catch (Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_UNBIND_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }


  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST;
  }


  public void writeTo(final ASN1Buffer buffer)
  {
    buffer.addNull(LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST);
  }


  public ASN1Element encodeProtocolOp()
  {
    return new ASN1Null(LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST);
  }


  public static UnbindRequestProtocolOp decodeProtocolOp(
                                             final ASN1Element element)
         throws LDAPException
  {
    try
    {
      ASN1Null.decodeAsNull(element);
      return new UnbindRequestProtocolOp();
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_UNBIND_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)),
           e);
    }
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
    buffer.append("UnbindRequestProtocolOp()");
  }
}
