

package com.hwlcn.ldap.ldap.protocol;



import com.hwlcn.ldap.asn1.ASN1Boolean;
import com.hwlcn.ldap.asn1.ASN1Buffer;
import com.hwlcn.ldap.asn1.ASN1BufferSequence;
import com.hwlcn.ldap.asn1.ASN1Element;
import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.asn1.ASN1Sequence;
import com.hwlcn.ldap.asn1.ASN1StreamReader;
import com.hwlcn.ldap.asn1.ASN1StreamReaderSequence;
import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.ModifyDNRequest;
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
public final class ModifyDNRequestProtocolOp
       implements ProtocolOp
{

  public static final byte TYPE_NEW_SUPERIOR = (byte) 0x80;



  private static final long serialVersionUID = 7514385089303489375L;


  private final boolean deleteOldRDN;


  private final String dn;


  private final String newRDN;

  private final String newSuperiorDN;


  public ModifyDNRequestProtocolOp(final String dn, final String newRDN,
                                   final boolean deleteOldRDN,
                                   final String newSuperiorDN)
  {
    this.dn            = dn;
    this.newRDN        = newRDN;
    this.deleteOldRDN  = deleteOldRDN;
    this.newSuperiorDN = newSuperiorDN;
  }




  public ModifyDNRequestProtocolOp(final ModifyDNRequest request)
  {
    dn            = request.getDN();
    newRDN        = request.getNewRDN();
    deleteOldRDN  = request.deleteOldRDN();
    newSuperiorDN = request.getNewSuperiorDN();
  }




  ModifyDNRequestProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      final ASN1StreamReaderSequence opSequence = reader.beginSequence();

      dn           = reader.readString();
      newRDN       = reader.readString();
      deleteOldRDN = reader.readBoolean();

      if (opSequence.hasMoreElements())
      {
        newSuperiorDN = reader.readString();
      }
      else
      {
        newSuperiorDN = null;
      }
    }
    catch (Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MODIFY_DN_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }



  public String getDN()
  {
    return dn;
  }



  public String getNewRDN()
  {
    return newRDN;
  }


  public boolean deleteOldRDN()
  {
    return deleteOldRDN;
  }


  public String getNewSuperiorDN()
  {
    return newSuperiorDN;
  }

  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST;
  }

  public ASN1Element encodeProtocolOp()
  {
    if (newSuperiorDN == null)
    {
      return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
           new ASN1OctetString(dn),
           new ASN1OctetString(newRDN),
           new ASN1Boolean(deleteOldRDN));
    }
    else
    {
      return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
           new ASN1OctetString(dn),
           new ASN1OctetString(newRDN),
           new ASN1Boolean(deleteOldRDN),
           new ASN1OctetString(TYPE_NEW_SUPERIOR, newSuperiorDN));
    }
  }


  public static ModifyDNRequestProtocolOp decodeProtocolOp(
                                               final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final String dn =
           ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
      final String newRDN =
           ASN1OctetString.decodeAsOctetString(elements[1]).stringValue();
      final boolean deleteOldRDN =
           ASN1Boolean.decodeAsBoolean(elements[2]).booleanValue();

      final String newSuperiorDN;
      if (elements.length > 3)
      {
        newSuperiorDN =
             ASN1OctetString.decodeAsOctetString(elements[3]).stringValue();
      }
      else
      {
        newSuperiorDN = null;
      }

      return new ModifyDNRequestProtocolOp(dn, newRDN, deleteOldRDN,
           newSuperiorDN);
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MODIFY_DN_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)),
           e);
    }
  }


  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST);
    buffer.addOctetString(dn);
    buffer.addOctetString(newRDN);
    buffer.addBoolean(deleteOldRDN);

    if (newSuperiorDN != null)
    {
      buffer.addOctetString(TYPE_NEW_SUPERIOR, newSuperiorDN);
    }
    opSequence.end();
  }


  public ModifyDNRequest toModifyDNRequest(final Control... controls)
  {
    return new ModifyDNRequest(dn, newRDN, deleteOldRDN, newSuperiorDN,
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
    buffer.append("ModifyDNRequestProtocolOp(dn='");
    buffer.append(dn);
    buffer.append("', newRDN='");
    buffer.append(newRDN);
    buffer.append("', deleteOldRDN=");
    buffer.append(deleteOldRDN);

    if (newSuperiorDN != null)
    {
      buffer.append(", newSuperiorDN='");
      buffer.append(newSuperiorDN);
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
